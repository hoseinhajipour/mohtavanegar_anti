<?php
/**
 * Scanner engine — chunked file walk + signature matching + htaccess audit.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Scanner {

	const STATE_KEY = 'scan';
	const CHUNK     = 40; // files per AJAX tick

	/**
	 * Start (or reset) a scan job.
	 *
	 * @param array $opts {scope: all|wp-content|core, deep: bool}
	 */
	public static function start( $opts = array() ) {
		$job_lock = mvn_job_lock_acquire( 'filesystem_mutation', 3600 );
		if ( ! $job_lock ) {
			return new WP_Error( 'job_locked', 'یک اسکن یا تعمیر دیگر در حال اجراست.' );
		}
		$scope       = isset( $opts['scope'] ) ? $opts['scope'] : 'all';
		$deep        = ! empty( $opts['deep'] );
		$incremental = ! isset( $opts['incremental'] ) || ! empty( $opts['incremental'] );
		$full        = ! empty( $opts['full'] );
		$scan_db     = ! isset( $opts['scan_db'] ) || ! empty( $opts['scan_db'] );
		$scan_as     = ! isset( $opts['scan_as'] ) || ! empty( $opts['scan_as'] );
		$scan_core   = ! isset( $opts['scan_core'] ) || ! empty( $opts['scan_core'] );
		$scan_repo   = ! isset( $opts['scan_repo'] ) || ! empty( $opts['scan_repo'] );
		$scan_media  = ! isset( $opts['scan_media'] ) || ! empty( $opts['scan_media'] );
		if ( 'wp-content' === $scope ) {
			$scan_core = false;
		}
		if ( $full ) {
			$incremental = false;
		}

		$files = array();
		if ( 'wp-content' === $scope || 'all' === $scope ) {
			$files = array_merge( $files, mvn_list_files( WP_CONTENT_DIR ) );
		}
		if ( 'core' === $scope || 'all' === $scope ) {
			// Core PHP only — skip wp-content (already covered) and bulky assets.
			$core_roots = array(
				ABSPATH . 'wp-admin',
				ABSPATH . 'wp-includes',
			);
			foreach ( $core_roots as $root ) {
				$files = array_merge( $files, mvn_list_files( $root ) );
			}
			foreach ( array( 'index.php', 'wp-config-sample.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'wp-cron.php', 'wp-login.php', 'wp-signup.php', 'wp-trackback.php', 'wp-comments-post.php', 'wp-mail.php', 'wp-activate.php', 'xmlrpc.php' ) as $root_file ) {
				if ( is_file( ABSPATH . $root_file ) ) {
					$files[] = $root_file;
				}
			}
		}

		// Always include every .htaccess under ABSPATH (rogue-htaccess hunt).
		$files = array_merge( $files, self::find_all_htaccess() );
		// Drop-ins, MU-plugins, .user.ini
		$files = array_merge( $files, MVN_Dropin_Audit::extra_scan_paths() );
		$files = array_values( array_unique( $files ) );

		// Filter by extension / size.
		$scannable  = mvn_scannable_extensions();
		$binary     = mvn_binary_extensions();
		$media_peek = mvn_media_peek_extensions();
		$filtered   = array();
		foreach ( $files as $rel ) {
			if ( mvn_is_skippable_dir( dirname( $rel ) ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
			$is_executable = in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'inc', 'js', 'htaccess', 'ini', 'zip', 'tar', 'gz', 'tgz' ), true );
			if ( preg_match( '#^wp-content/(?:cache|upgrade|uploads/cache)(?:/|$)#', $rel ) && ! $is_executable ) {
				continue;
			}
			// Bare .htaccess / .user.ini have empty or special names.
			$name = basename( $rel );
			if ( '.htaccess' === $name || 'htaccess' === $name || '.user.ini' === $name || 'user.ini' === $name || 'php.ini' === $name ) {
				$filtered[] = $rel;
				continue;
			}
			// Skip uploaded images from the default scan catalog to avoid repeated
			// false positives on benign media and metadata payload noise.
			if ( $scan_media && in_array( $ext, $media_peek, true ) && 0 === strpos( $rel, 'wp-content/uploads/' ) ) {
				continue;
			}
			if ( in_array( $ext, array( 'zip', 'tar', 'gz', 'tgz' ), true ) ) {
				$filtered[] = $rel;
				continue;
			}
			if ( in_array( $ext, $binary, true ) ) {
				continue;
			}
			if ( ! in_array( $ext, $scannable, true ) ) {
				// Deep mode: also peek at extensionless PHP-looking files under uploads.
				if ( ! $deep ) {
					continue;
				}
			}
			$filtered[] = $rel;
		}
		$filtered = array_values( array_unique( $filtered ) );

		// Incremental: skip unchanged files that were clean in the last scan.
		$to_scan           = array();
		$skipped_unchanged = 0;
		foreach ( $filtered as $rel ) {
			if ( ! $incremental ) {
				$to_scan[] = $rel;
				continue;
			}
			$abs = mvn_abs_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				$to_scan[] = $rel;
				continue;
			}
			$mtime = @filemtime( $abs );
			$size  = @filesize( $abs );
			if ( false === $mtime || false === $size ) {
				$to_scan[] = $rel;
				continue;
			}
			$sha256 = @hash_file( 'sha256', $abs );
			if ( is_string( $sha256 ) && MVN_File_Index::is_unchanged_clean( $rel, $mtime, $size, $sha256 ) ) {
				$skipped_unchanged++;
				continue;
			}
			$to_scan[] = $rel;
		}

		$state = array(
			'id'          => gmdate( 'YmdHis' ) . '-' . wp_generate_password( 6, false ),
			'started_at'  => gmdate( 'c' ),
			'updated_at'  => gmdate( 'c' ),
			'scope'       => $scope,
			'deep'        => $deep,
			'incremental' => $incremental ? 1 : 0,
			'scan_db'     => $scan_db ? 1 : 0,
			'scan_as'     => $scan_as ? 1 : 0,
			'scan_core'   => $scan_core ? 1 : 0,
			'scan_repo'   => $scan_repo ? 1 : 0,
			'scan_media'  => $scan_media ? 1 : 0,
			'phase'       => 'files',
			'catalog'     => count( $filtered ),
			'skipped_unchanged' => $skipped_unchanged,
			'status'      => 'running',
			'total'       => count( $to_scan ),
			'processed'   => 0,
			'cursor'      => 0,
			'files'       => $to_scan,
			'all_files'   => $filtered,
			'issues'      => array(),
			'lock_token'  => $job_lock,
			'stats'       => array(
				'critical' => 0,
				'warning'  => 0,
				'info'     => 0,
				'htaccess' => 0,
				'php'      => 0,
				'js'       => 0,
				'db'       => 0,
				'as'       => 0,
				'core'     => 0,
				'repo'     => 0,
				'dropin'   => 0,
				'ghost'    => 0,
				'polyglot' => 0,
				'hash'     => 0,
				'behavior' => 0,
				'archive'  => 0,
				'wpconfig' => 0,
				'symlink'  => 0,
			),
		);
		foreach ( MVN_WPConfig_Audit::audit() as $finding ) {
			if ( self::add_finding( $state, $finding, '', '' ) ) {
				$state['stats']['wpconfig']++;
			}
		}
		foreach ( mvn_list_symlinks( array( ABSPATH, WP_CONTENT_DIR ) ) as $link ) {
			if ( self::add_finding(
				$state,
				array(
					'rel' => $link['rel'], 'sig' => 'suspicious_symlink',
					'label' => $link['outside'] ? 'symlink خارج از root مجاز' : 'symlink شناسایی شد',
					'severity' => $link['outside'] ? 'critical' : 'warning',
					'detail' => 'مقصد: ' . $link['target'] . ' — مقصد traverse نشد.',
					'action' => 'manual_review', 'confidence' => $link['outside'] ? 92 : 65,
					'source' => 'symlink',
					'evidence' => array( array( 'engine' => 'inventory', 'signal' => 'symlink' ) ),
				),
				'',
				''
			) ) {
				$state['stats']['symlink']++;
			}
		}
		MVN_Local_Baseline::audit( $state );
		mvn_state_write( self::STATE_KEY, $state );
		// Structural drop-in audit once at start.
		MVN_Dropin_Audit::audit( $state );
		// Known malware plugins + ghosts hidden via all_plugins / admin filters.
		MVN_Ghost_Plugins::audit( $state );
		mvn_state_write( self::STATE_KEY, $state );
		update_option( MVN_OPTION_LASTSCAN, array( 'id' => $state['id'], 'started_at' => $state['started_at'] ), false );
		mvn_log( 'Scan started: ' . $state['id'] . ' catalog=' . count( $filtered ) . ' to_scan=' . $state['total'] . ' skipped=' . $skipped_unchanged );
		return $state;
	}

	/**
	 * Process the next CHUNK of files. Returns updated state.
	 */
	public static function tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) || 'running' !== $state['status'] ) {
			return $state;
		}

		$phase = isset( $state['phase'] ) ? $state['phase'] : 'files';

		if ( 'core' === $phase ) {
			MVN_Core_Integrity::tick( $state );
			$state['updated_at'] = gmdate( 'c' );
			if ( MVN_Core_Integrity::is_done( $state ) ) {
				$state['core_files']  = array();
				$state['core_extras'] = array();
				self::after_core_phase( $state );
			} else {
				self::commit_tick_state( $state );
			}
			return $state;
		}

		if ( 'repo' === $phase ) {
			MVN_Repo_Integrity::tick( $state );
			$state['updated_at'] = gmdate( 'c' );
			if ( MVN_Repo_Integrity::is_done( $state ) ) {
				$state['repo_jobs']       = array();
				$state['repo_file_queue'] = array();
				$state['repo_context']    = null;
				self::after_repo_phase( $state );
			} else {
				self::commit_tick_state( $state );
			}
			return $state;
		}

		if ( 'db' === $phase ) {
			MVN_DB_Scanner::tick( $state );
			$state['updated_at'] = gmdate( 'c' );
			if ( MVN_DB_Scanner::is_done( $state ) ) {
				self::after_db_phase( $state );
			} else {
				self::commit_tick_state( $state );
			}
			return $state;
		}

		if ( 'as' === $phase ) {
			MVN_AS_Scanner::tick( $state );
			$state['updated_at'] = gmdate( 'c' );
			if ( MVN_AS_Scanner::is_done( $state ) ) {
				self::after_as_phase( $state );
			} else {
				self::commit_tick_state( $state );
			}
			return $state;
		}

		if ( 'persistence' === $phase ) {
			MVN_Persistence_Scanner::tick( $state );
			$state['updated_at'] = gmdate( 'c' );
			if ( MVN_Persistence_Scanner::is_done( $state ) ) {
				self::finish_scan( $state );
			} else {
				self::commit_tick_state( $state );
			}
			return $state;
		}

		$sigs   = mvn_signatures();
		$start  = (int) $state['cursor'];
		$total  = (int) $state['total'];
		$end    = min( $start + self::CHUNK, $total );
		$files  = isset( $state['files'] ) ? $state['files'] : array();

		for ( $i = $start; $i < $end; $i++ ) {
			$rel = $files[ $i ];
			self::scan_one( $rel, $sigs, $state );
		}

		MVN_File_Index::flush();

		$state['cursor']     = $end;
		$state['processed']  = $end;
		$state['updated_at'] = gmdate( 'c' );

		if ( $end >= $total ) {
			self::after_files_phase( $state );
		} else {
			self::commit_tick_state( $state );
		}

		return $state;
	}

	/**
	 * Persist tick progress without clobbering a concurrent pause/stop.
	 */
	private static function commit_tick_state( &$state ) {
		$latest = mvn_state_read( self::STATE_KEY );
		if ( ! empty( $latest['status'] ) && 'paused' === $latest['status'] ) {
			$state['status']    = 'paused';
			$state['paused_at'] = isset( $latest['paused_at'] ) ? $latest['paused_at'] : gmdate( 'c' );
		} elseif ( ! empty( $latest['status'] ) && 'stopped' === $latest['status'] ) {
			return;
		}
		mvn_state_write( self::STATE_KEY, $state );
	}

	/**
	 * File phase finished — move to core checksum, DB, or finalize.
	 */
	private static function after_files_phase( &$state ) {
		MVN_File_Index::flush();
		if ( ! empty( $state['all_files'] ) ) {
			MVN_File_Index::prune( $state['all_files'] );
		}
		$state['files']          = array();
		$state['all_files']      = array();
		$state['file_total']     = isset( $state['total'] ) ? (int) $state['total'] : 0;
		$state['file_processed'] = isset( $state['processed'] ) ? (int) $state['processed'] : 0;

		if ( self::should_scan_core( $state ) ) {
			MVN_Core_Integrity::begin_phase( $state );
			if ( MVN_Core_Integrity::is_done( $state ) ) {
				$state['core_files']  = array();
				$state['core_extras'] = array();
				self::after_core_phase( $state );
			} else {
				mvn_state_write( self::STATE_KEY, $state );
			}
			return;
		}

		self::after_core_phase( $state );
	}

	/**
	 * Core checksum phase finished — move to repo integrity, DB, or finalize.
	 */
	private static function after_core_phase( &$state ) {
		if ( ! empty( $state['scan_repo'] ) ) {
			MVN_Repo_Integrity::begin_phase( $state );
			if ( MVN_Repo_Integrity::is_done( $state ) ) {
				self::after_repo_phase( $state );
			} else {
				mvn_state_write( self::STATE_KEY, $state );
			}
			return;
		}
		self::after_repo_phase( $state );
	}

	/**
	 * Repo integrity finished — move to DB, AS, or finalize.
	 */
	private static function after_repo_phase( &$state ) {
		if ( ! empty( $state['scan_db'] ) ) {
			MVN_DB_Scanner::begin_phase( $state );
			mvn_state_write( self::STATE_KEY, $state );
			return;
		}
		self::after_db_phase( $state );
	}

	/**
	 * DB phase finished — move to Action Scheduler or finalize.
	 */
	private static function after_db_phase( &$state ) {
		if ( ! empty( $state['scan_as'] ) ) {
			MVN_AS_Scanner::begin_phase( $state );
			if ( MVN_AS_Scanner::is_done( $state ) ) {
				self::after_as_phase( $state );
			} else {
				mvn_state_write( self::STATE_KEY, $state );
			}
			return;
		}
		self::after_as_phase( $state );
	}

	/**
	 * AS phase finished — persistence / reinfection correlation, then finalize.
	 */
	private static function after_as_phase( &$state ) {
		MVN_Persistence_Scanner::begin_phase( $state );
		if ( MVN_Persistence_Scanner::is_done( $state ) ) {
			self::finish_scan( $state );
		} else {
			mvn_state_write( self::STATE_KEY, $state );
		}
	}

	private static function should_scan_core( $state ) {
		if ( empty( $state['scan_core'] ) ) {
			return false;
		}
		$scope = isset( $state['scope'] ) ? $state['scope'] : 'all';
		return in_array( $scope, array( 'all', 'core' ), true );
	}

	/**
	 * Pause a running scan (keeps progress for resume).
	 *
	 * @return array|WP_Error
	 */
	public static function pause() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) ) {
			return new WP_Error( 'no_scan', 'اسکن فعالی وجود ندارد.' );
		}
		if ( 'running' !== $state['status'] ) {
			return new WP_Error( 'not_running', 'اسکن در حال اجرا نیست.' );
		}
		MVN_File_Index::flush();
		$state['status']     = 'paused';
		$state['paused_at']  = gmdate( 'c' );
		$state['updated_at'] = gmdate( 'c' );
		mvn_state_write( self::STATE_KEY, $state );
		mvn_log( 'Scan paused: ' . ( isset( $state['id'] ) ? $state['id'] : '' ) . ' processed=' . ( isset( $state['processed'] ) ? $state['processed'] : 0 ) );
		return $state;
	}

	/**
	 * Resume a paused scan.
	 *
	 * @return array|WP_Error
	 */
	public static function resume() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) ) {
			return new WP_Error( 'no_scan', 'اسکن فعالی وجود ندارد.' );
		}
		if ( 'paused' !== $state['status'] ) {
			return new WP_Error( 'not_paused', 'اسکن در حالت توقف موقت نیست.' );
		}
		$state['status']     = 'running';
		$state['updated_at'] = gmdate( 'c' );
		unset( $state['paused_at'] );
		mvn_state_write( self::STATE_KEY, $state );
		mvn_log( 'Scan resumed: ' . ( isset( $state['id'] ) ? $state['id'] : '' ) );
		return $state;
	}

	/**
	 * Stop scan permanently and keep findings found so far.
	 *
	 * @return array|WP_Error
	 */
	public static function stop() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) ) {
			return new WP_Error( 'no_scan', 'اسکن فعالی وجود ندارد.' );
		}
		if ( ! in_array( $state['status'], array( 'running', 'paused' ), true ) ) {
			return new WP_Error( 'not_active', 'اسکن فعالی برای توقف وجود ندارد.' );
		}
		MVN_File_Index::flush();
		self::finish_scan( $state, 'stopped' );
		mvn_log( 'Scan stopped: issues=' . ( isset( $state['issues'] ) ? count( $state['issues'] ) : 0 ) );
		return $state;
	}

	/**
	 * Finalize scan — persist issues and last-scan summary.
	 *
	 * @param array  $state  Scan state.
	 * @param string $status Final status: done|stopped.
	 */
	private static function finish_scan( &$state, $status = 'done' ) {
		$state['status']      = in_array( $status, array( 'done', 'stopped' ), true ) ? $status : 'done';
		$state['finished_at'] = gmdate( 'c' );
		$issues               = self::sort_issues( isset( $state['issues'] ) ? $state['issues'] : array() );
		$previous_incidents = MVN_Incidents::all();
		MVN_Incidents::store_issues( $issues );
		$incidents = MVN_Incidents::sync_scan( $issues, isset( $state['id'] ) ? $state['id'] : '' );
		foreach ( $incidents as $incident_id => $incident ) {
			if ( empty( $previous_incidents[ $incident_id ] )
				&& ! empty( $incident['finding']['severity'] )
				&& 'critical' === $incident['finding']['severity'] ) {
				MVN_Notify::critical( $incident );
				MVN_Hardening::revoke_admin_sessions_after_incident();
			}
		}

		$file_total = isset( $state['file_total'] ) ? (int) $state['file_total'] : (int) ( isset( $state['total'] ) ? $state['total'] : 0 );
		$db_total   = isset( $state['db_total'] ) ? (int) $state['db_total'] : 0;

		update_option(
			MVN_OPTION_LASTSCAN,
			array(
				'id'                => isset( $state['id'] ) ? $state['id'] : '',
				'started_at'        => isset( $state['started_at'] ) ? $state['started_at'] : '',
				'finished_at'       => $state['finished_at'],
				'status'            => $state['status'],
				'total'             => $file_total + $db_total,
				'file_total'        => $file_total,
				'db_total'          => $db_total,
				'catalog'           => isset( $state['catalog'] ) ? $state['catalog'] : $file_total,
				'skipped_unchanged' => isset( $state['skipped_unchanged'] ) ? $state['skipped_unchanged'] : 0,
				'incremental'       => ! empty( $state['incremental'] ),
				'scan_db'           => ! empty( $state['scan_db'] ),
				'scan_as'           => ! empty( $state['scan_as'] ),
				'scan_core'         => ! empty( $state['scan_core'] ),
				'scan_repo'         => ! empty( $state['scan_repo'] ),
				'stats'             => isset( $state['stats'] ) ? $state['stats'] : array(),
				'issue_count'       => count( $issues ),
			),
			false
		);
		mvn_log( 'Scan ' . $state['status'] . ': issues=' . count( $issues ) . ' core=' . ( isset( $state['stats']['core'] ) ? $state['stats']['core'] : 0 ) . ' db=' . ( isset( $state['stats']['db'] ) ? $state['stats']['db'] : 0 ) . ' as=' . ( isset( $state['stats']['as'] ) ? $state['stats']['as'] : 0 ) );
		$state['issues']      = $issues;
		$state['files']       = array();
		$state['all_files']   = array();
		$state['core_files']  = array();
		$state['core_extras'] = array();
		if ( ! empty( $state['lock_token'] ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $state['lock_token'] );
		}
		mvn_state_write( self::STATE_KEY, $state );
	}

	/**
	 * Scan a single relative path and append findings to $state.
	 */
	private static function scan_one( $rel, $sigs, &$state ) {
		if ( mvn_is_skippable_scan_file( $rel ) ) {
			return;
		}

		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return;
		}
		$size = @filesize( $abs );
		$mtime = @filemtime( $abs );
		if ( false === $mtime ) {
			$mtime = 0;
		}
		$sha256 = @hash_file( 'sha256', $abs );
		$ext     = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, array( 'zip', 'tar', 'gz', 'tgz' ), true ) ) {
			$archive_issues = MVN_Archive_Scanner::scan( $abs, $rel );
			foreach ( $archive_issues as $finding ) {
				if ( self::add_finding( $state, $finding, '', is_string( $sha256 ) ? $sha256 : '' ) ) {
					$state['stats']['archive']++;
					$state['stats'][ $finding['severity'] ]++;
				}
			}
			MVN_File_Index::mark( $rel, empty( $archive_issues ), $mtime, $size, is_string( $sha256 ) ? $sha256 : '' );
			return;
		}
		// Media polyglot: allow up to 8MB peek; other files stay at 5MB.
		$is_media_peek = in_array( strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) ), mvn_media_peek_extensions(), true )
			&& 0 === strpos( $rel, 'wp-content/uploads/' );
		$max_size = $is_media_peek ? 8 * 1024 * 1024 : 5 * 1024 * 1024;
		if ( false === $size ) {
			return;
		}
		if ( $size > $max_size ) {
			$half    = (int) floor( $max_size / 2 );
			$first   = @file_get_contents( $abs, false, null, 0, $half );
			$last    = @file_get_contents( $abs, false, null, max( 0, $size - $half ), $half );
			$content = (string) $first . "\n/* MVN_PARTIAL_LARGE_FILE */\n" . (string) $last;
		} else {
			$content = @file_get_contents( $abs );
		}
		if ( false === $content || '' === $content ) {
			MVN_File_Index::mark( $rel, true, $mtime, $size, is_string( $sha256 ) ? $sha256 : '' );
			return;
		}

		$file_hash  = $size > $max_size ? (string) @md5_file( $abs ) : md5( $content );
		$had_issues = false;

		$name = basename( $rel );
		$ext  = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );

		// Path IoC: xdav-tracker / companion malware plugin files.
		$ioc = MVN_Ghost_Plugins::path_ioc_match( $rel );
		if ( $ioc ) {
			if ( self::add_finding(
				$state,
				array(
					'rel'      => $rel,
					'sig'      => 'known_malware_plugin',
					'label'    => 'فایل بدافزار شناخته‌شده (IoC مسیر): ' . $ioc,
					'severity' => 'critical',
					'detail'   => 'نام/مسیر مطابق خانواده xdav-tracker یا پلاگین همراه است.',
					'action'   => 'quarantine_delete',
					'snippet'  => self::snippet( $content, 0, 160 ),
					'source'   => 'ghost',
				),
				$content,
				$file_hash
			) ) {
				$had_issues = true;
				$state['stats']['critical']++;
				if ( ! isset( $state['stats']['ghost'] ) ) {
					$state['stats']['ghost'] = 0;
				}
				$state['stats']['ghost']++;
			}
		}
		$is_htaccess = ( '.htaccess' === $name || 'htaccess' === $name );
		$is_ini      = ( '.user.ini' === $name || 'user.ini' === $name || 'php.ini' === $name || 'ini' === $ext );
		$is_php      = in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'inc' ), true );
		$is_js       = ( 'js' === $ext );
		$is_svg      = ( 'svg' === $ext );

		// Known malware hash match (pack).
		$hash_hit = MVN_Signature_Pack::match_hash( $content );
		if ( $hash_hit ) {
			if ( self::add_finding(
				$state,
				array(
					'rel'      => $rel,
					'sig'      => 'known_malware_hash',
					'label'    => $hash_hit['label'],
					'severity' => $hash_hit['severity'],
					'detail'   => strtoupper( $hash_hit['algo'] ) . ' ' . $hash_hit['hash'],
					'action'   => 'quarantine_delete',
					'snippet'  => self::snippet( $content, 0, 120 ),
				),
				$content,
				$file_hash
			) ) {
				$had_issues = true;
				$state['stats']['critical']++;
				$state['stats']['hash']++;
			}
		}

		// Polyglot: PHP/webshell markers inside media under uploads.
		if ( $is_media_peek && self::content_has_php_payload( $content ) ) {
			if ( self::add_finding(
				$state,
				array(
					'rel'      => $rel,
					'sig'      => 'polyglot_php_in_media',
					'label'    => 'کد PHP جاسازی‌شده در فایل رسانه (polyglot)',
					'severity' => 'critical',
					'detail'   => 'تصویر/مدیا حاوی تگ یا payload اجرایی PHP است.',
					'action'   => 'quarantine_delete',
					'snippet'  => self::snippet( $content, max( 0, self::php_payload_offset( $content ) ), 180 ),
				),
				$content,
				$file_hash
			) ) {
				$had_issues = true;
				$state['stats']['critical']++;
				$state['stats']['polyglot']++;
			}
			MVN_File_Index::mark( $rel, ! $had_issues, $mtime, $size, is_string( $sha256 ) ? $sha256 : '' );
			return; // Skip noisy full regex on binary media.
		}

		// Rogue htaccess: any .htaccess that is NOT the site root one is suspicious
		// if it contains PHP-handler / auto_prepend / RewriteEngine+payload.
		if ( $is_htaccess ) {
			$root_ht = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/.htaccess';
			$is_root = ( str_replace( '\\', '/', $abs ) === $root_ht );

			if ( ! $is_root ) {
				// Always flag non-root htaccess that touches PHP handlers or rewrite.
				$rogue_hit = false;
				$reason    = '';
				if ( preg_match( '/php_value|php_flag|auto_prepend_file|auto_append_file|SetHandler|AddHandler|AddType/i', $content ) ) {
					$rogue_hit = true;
					$reason    = 'حاوی دستور PHP handler / auto_prepend';
				} elseif ( preg_match( '/RewriteEngine\s+On/i', $content ) && preg_match( '/RewriteRule/i', $content ) ) {
					$rogue_hit = true;
					$reason    = 'حاوی RewriteRule در پوشه غیرریشه (الگوی ویروس جدید)';
				} elseif ( preg_match( '/Deny from|Require all denied|Order\s+Allow,Deny/i', $content ) && false !== strpos( $rel, 'wp-content/uploads' ) ) {
					// Uploads htaccess that only denies PHP is often legitimate; skip pure deny.
					$rogue_hit = false;
				} else {
					// Default: flag ANY rogue htaccess outside known safe locations.
					$safe_dirs = array(
						'wp-content/mvn-data',
						'wp-content/uploads', // uploads often has a deny-php htaccess
					);
					$safe = false;
					foreach ( $safe_dirs as $sd ) {
						if ( 0 === strpos( $rel, $sd . '/' ) || $rel === $sd . '/.htaccess' ) {
							// Only safe if the content is a pure "deny php" style.
							if ( preg_match( '/<(?:Files|FilesMatch)[^>]*>[\s\S]*?(?:Require all denied|Deny from all)/i', $content )
								&& ! preg_match( '/php_value|auto_prepend|SetHandler|RewriteRule/i', $content ) ) {
								$safe = true;
							}
							break;
						}
					}
					if ( ! $safe ) {
						$rogue_hit = true;
						$reason    = 'فایل .htaccess غیرمجاز در پوشه (الگوی ویروس جدید)';
					}
				}

				if ( $rogue_hit ) {
					if ( self::add_finding(
						$state,
						array(
							'rel'      => $rel,
							'sig'      => 'rogue_htaccess',
							'label'    => 'htaccess جعلی / مخرب',
							'severity' => 'critical',
							'detail'   => $reason,
							'action'   => 'delete_htaccess',
							'snippet'  => self::snippet( $content, 0, 180 ),
						),
						$content,
						$file_hash
					) ) {
						$had_issues = true;
						$state['stats']['htaccess']++;
					}
				}
			}
		}

		$scope_key = $is_htaccess ? 'htaccess' : ( $is_php ? 'php' : ( $is_js ? 'js' : ( $is_svg ? 'svg' : ( $is_ini ? 'ini' : 'any' ) ) ) );

		if ( $is_php ) {
			$behavior = MVN_Behavior_Scanner::analyze( $rel, $content );
			if ( $behavior && self::add_finding( $state, $behavior, $content, $file_hash ) ) {
				$had_issues = true;
				$state['stats']['behavior']++;
				$state['stats'][ $behavior['severity'] ]++;
			}
		}

		foreach ( $sigs as $sig ) {
			$sig_scope = $sig['scope'];
			if ( 'any' !== $sig_scope ) {
				if ( 'php' === $sig_scope && ! $is_php ) {
					continue;
				}
				if ( 'js' === $sig_scope && ! $is_js ) {
					continue;
				}
				if ( 'htaccess' === $sig_scope && ! $is_htaccess ) {
					continue;
				}
				if ( 'svg' === $sig_scope && ! $is_svg ) {
					continue;
				}
				if ( 'ini' === $sig_scope && ! $is_ini ) {
					continue;
				}
			}
			if ( @preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$offset = isset( $m[0][1] ) ? (int) $m[0][1] : 0;
				$match  = isset( $m[0][0] ) ? $m[0][0] : '';
				if ( self::is_false_positive( $sig['id'], $rel, $content, $offset, $match ) ) {
					continue;
				}
				$action = 'none' === $sig['clean'] ? 'quarantine' : 'clean';
				if ( $is_htaccess && 'none' === $sig['clean'] ) {
					$action = 'delete_htaccess';
				}
				if ( in_array( $sig['id'], array( 'xdav_tracker_markers', 'zonal_runner_tap_markers', 'shutdown_js_inject', 'hide_plugin_user_hooks', 'stealth_admin_recreate' ), true ) ) {
					$action = 'quarantine_delete';
				}
				if ( ! self::add_finding(
					$state,
					array(
						'rel'      => $rel,
						'sig'      => $sig['id'],
						'label'    => $sig['label'],
						'severity' => $sig['severity'],
						'detail'   => '',
						'action'   => $action,
						'clean'    => $sig['clean'],
						'snippet'  => self::snippet( $content, $offset, 220 ),
					),
					$content,
					$file_hash
				) ) {
					continue;
				}
				$had_issues = true;
				$key = $sig['severity'];
				if ( isset( $state['stats'][ $key ] ) ) {
					$state['stats'][ $key ]++;
				}
				if ( $is_php ) {
					$state['stats']['php']++;
				} elseif ( $is_js ) {
					$state['stats']['js']++;
				} elseif ( $is_htaccess ) {
					$state['stats']['htaccess']++;
				}
			}
		}

		// Extra: PHP files sitting directly inside uploads (almost always malware).
		if ( $is_php && 0 === strpos( $rel, 'wp-content/uploads/' ) ) {
			if ( self::add_finding(
				$state,
				array(
					'rel'      => $rel,
					'sig'      => 'php_in_uploads',
					'label'    => 'فایل PHP داخل پوشه uploads',
					'severity' => 'critical',
					'detail'   => 'وجود PHP در uploads تقریباً همیشه نشانه بدافزار است.',
					'action'   => 'quarantine_delete',
					'snippet'  => self::snippet( $content, 0, 160 ),
				),
				$content,
				$file_hash
			) ) {
				$had_issues = true;
				$state['stats']['critical']++;
			}
		}

		MVN_File_Index::mark( $rel, ! $had_issues, $mtime, $size, is_string( $sha256 ) ? $sha256 : '' );
	}

	/**
	 * Detect PHP / webshell markers inside binary/media content.
	 */
	public static function content_has_php_payload( $content ) {
		if ( ! is_string( $content ) || '' === $content ) {
			return false;
		}

		$prefix = substr( $content, 0, 16 );
		$is_image = false;
		if ( 0 === strpos( $prefix, "\x89PNG\r\n\x1a\n" )
			|| 0 === strpos( $prefix, "\xFF\xD8\xFF" )
			|| 0 === strpos( $prefix, 'GIF87a' )
			|| 0 === strpos( $prefix, 'GIF89a' )
			|| 0 === strpos( $prefix, 'RIFF' )
			|| 0 === strpos( $prefix, "\x42\x4D" )
			|| 0 === strpos( $prefix, "\x00\x00\x01\x00" ) ) {
			$is_image = true;
		}

		if ( $is_image ) {
			$php_like = preg_match( '/<\?(?:php|=)/i', $content );
			if ( ! $php_like ) {
				return false;
			}
			return (bool) preg_match( '/\b(?:eval|assert|shell_exec|passthru|system|base64_decode|file_put_contents|file_get_contents|fopen|curl_exec)\s*\(/i', $content )
				&& ( preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i', $content ) || preg_match( '/\$\w+\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i', $content ) );
		}

		if ( false !== stripos( $content, '<?php' ) || false !== strpos( $content, '<?=' ) ) {
			return true;
		}
		if ( preg_match( '/\b(?:eval|assert|shell_exec|passthru|system|base64_decode)\s*\(/i', $content ) ) {
			return true;
		}
		if ( preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i', $content ) && preg_match( '/\b(?:eval|assert|system|exec|passthru|shell_exec)\b/i', $content ) ) {
			return true;
		}
		return false;
	}

	private static function php_payload_offset( $content ) {
		$pos = stripos( $content, '<?php' );
		if ( false !== $pos ) {
			return (int) $pos;
		}
		$pos = strpos( $content, '<?=' );
		return false !== $pos ? (int) $pos : 0;
	}

	private static function add_issue( &$state, $issue, $content = '', $file_hash = '' ) {
		return self::add_finding( $state, $issue, $content, $file_hash );
	}

	/**
	 * Add a finding (file or DB) to scan state.
	 *
	 * @return bool Whether the finding was added.
	 */
	public static function add_finding( &$state, $issue, $content = '', $value_hash = '' ) {
		$rel = isset( $issue['rel'] ) ? $issue['rel'] : '';
		$sig = isset( $issue['sig'] ) ? $issue['sig'] : '';

		if ( MVN_Ignore_List::is_ignored( $rel, $sig, $value_hash ) ) {
			return false;
		}

		// Deduplicate by rel+sig.
		$key = $rel . '|' . $sig;
		foreach ( $state['issues'] as $index => $existing ) {
			if ( $existing['rel'] . '|' . $existing['sig'] === $key ) {
				if ( ! empty( $issue['evidence'] ) ) {
					$current = isset( $state['issues'][ $index ]['evidence'] ) ? $state['issues'][ $index ]['evidence'] : array();
					$state['issues'][ $index ]['evidence'] = array_values( array_merge( $current, $issue['evidence'] ) );
				}
				return false;
			}
		}

		if ( empty( $issue['source'] ) ) {
			if ( 0 === strpos( $rel, 'db:' ) ) {
				$issue['source'] = 'db';
			} elseif ( 0 === strpos( $rel, 'as:' ) ) {
				$issue['source'] = 'as';
			} else {
				$issue['source'] = 'file';
			}
		}

		$severity   = isset( $issue['severity'] ) ? $issue['severity'] : 'warning';
		$computed   = mvn_compute_confidence( $sig, $severity, $rel, $content );
		$confidence = isset( $issue['confidence'] ) ? max( $computed, (int) $issue['confidence'] ) : $computed;
		if ( empty( $issue['evidence'] ) ) {
			$issue['evidence'] = array( array( 'engine' => $issue['source'], 'signal' => $sig ) );
		}
		foreach ( $state['issues'] as $existing ) {
			if ( isset( $existing['rel'] ) && $existing['rel'] === $rel && ! empty( $existing['sig'] ) ) {
				$issue['evidence'][] = array( 'engine' => isset( $existing['source'] ) ? $existing['source'] : 'signature', 'signal' => $existing['sig'] );
			}
		}
		$issue['evidence'] = array_slice( $issue['evidence'], 0, 20 );

		$issue['id']          = md5( $key );
		$issue['confidence']  = $confidence;
		$issue['conf_label']  = mvn_confidence_label( $confidence );
		$issue['file_hash']   = $value_hash;
		$issue['content_hash'] = $value_hash;
		$state['issues'][]    = $issue;
		return true;
	}

	/**
	 * Drop known false positives for DB content.
	 */
	public static function is_db_false_positive( $sig_id, $table, $row, $column, $content, $offset, $match ) {
		if ( 'options' === $table ) {
			$name = isset( $row['option_name'] ) ? $row['option_name'] : '';
			if ( $name && mvn_db_is_benign_option( $name ) ) {
				return true;
			}
			if ( 'option_value' === $column && function_exists( 'is_serialized' ) && is_serialized( $content ) ) {
				if ( ! in_array( $sig_id, array( 'eval_decoder', 'eval_request', 'shell_exec_request', 'webshell_markers', 'nested_decoders', 'preg_replace_e' ), true ) ) {
					return true;
				}
			}
		}
		if ( 'postmeta' === $table && isset( $row['meta_key'] ) && mvn_db_is_benign_meta_key( $row['meta_key'] ) ) {
			return true;
		}
		// Schema.org / FAQ JSON-LD is not an SVG script payload.
		if ( 'svg_script_payload' === $sig_id ) {
			$ctx = substr( $content, max( 0, $offset - 80 ), strlen( (string) $match ) + 160 );
			if ( preg_match( '/application\/ld\+json|FAQPage|schema\.org|@type|uagb\/faq/i', $ctx ) ) {
				return true;
			}
			if ( ! preg_match( '/<svg[\s>]/i', substr( $content, max( 0, $offset - 500 ), 700 ) ) ) {
				return true;
			}
		}
		return (bool) apply_filters( 'mvn_db_scan_false_positive', false, $sig_id, $table, $row, $column, $content, $offset, $match );
	}

	public static function sort_issues( $issues ) {
		if ( ! is_array( $issues ) ) {
			return array();
		}
		usort(
			$issues,
			function ( $a, $b ) {
				$ca = isset( $a['confidence'] ) ? (int) $a['confidence'] : 0;
				$cb = isset( $b['confidence'] ) ? (int) $b['confidence'] : 0;
				if ( $ca !== $cb ) {
					return $cb - $ca;
				}
				$sa = isset( $a['severity'] ) ? $a['severity'] : '';
				$sb = isset( $b['severity'] ) ? $b['severity'] : '';
				$rank = array( 'critical' => 3, 'warning' => 2, 'info' => 1 );
				$ra   = isset( $rank[ $sa ] ) ? $rank[ $sa ] : 0;
				$rb   = isset( $rank[ $sb ] ) ? $rank[ $sb ] : 0;
				return $rb - $ra;
			}
		);
		return $issues;
	}

	private static function snippet( $content, $offset, $len ) {
		$start = max( 0, $offset - 40 );
		$chunk = substr( $content, $start, $len );
		$chunk = preg_replace( '/\s+/', ' ', $chunk );
		return mb_substr( $chunk, 0, $len );
	}

	/**
	 * Drop known false positives (legitimate plugin / security-tool code).
	 */
	private static function is_false_positive( $sig_id, $rel, $content, $offset, $match ) {
		switch ( $sig_id ) {
			case 'chr_chain':
				// gzip / tar magic bytes: chr(31).chr(139)...
				$ctx = substr( $content, max( 0, $offset - 30 ), strlen( $match ) + 120 );
				if ( preg_match( '/\bchr\s*\(\s*31\s*\)/i', $ctx ) && preg_match( '/\bchr\s*\(\s*139\s*\)/i', $ctx ) ) {
					return true;
				}
				if ( preg_match( '/tar-archiver|gzencode|gzcompress|NOSONAR/i', $ctx ) ) {
					return true;
				}
				break;

			case 'hidden_iframe':
				// WordPress embed, Plupload/Moxie, LiteSpeed crawler, jQuery BlockUI.
				if ( preg_match( '/\bsandbox=|wp-embed|plupload|moxie|src\s*=\s*["\']javascript:|litespeedHiddenIframe|class=["\']blockUI|blockUI/i', $match ) ) {
					return true;
				}
				if ( preg_match( '#/(litespeed-cache|wp-optimize)/#', $rel ) ) {
					return true;
				}
				break;

			case 'variable_variables_eval':
				// Comments mentioning $_REQUEST (e.g. wp-settings.php).
				$before = substr( $content, max( 0, $offset - 120 ), min( 120, $offset ) );
				if ( preg_match( '/\/\/|\/\*|\*/', $before ) && false === strpos( substr( $content, $offset, 80 ), ';' ) ) {
					return true;
				}
				// Allow OOP dynamic calls like $this->$action( $_REQUEST ) in Elementor etc.
				if ( $offset >= 2 && '->' === substr( $content, $offset - 2, 2 ) ) {
					return true;
				}
				if ( $offset >= 3 && '->' === substr( $content, $offset - 3, 2 ) ) {
					return true;
				}
				// Whitelisted sanitize callback pattern: $sanitize_func( $_POST[ ... ] )
				$ctx = substr( $content, max( 0, $offset - 40 ), 160 );
				if ( preg_match( '/\$sanitize_(?:func|callback|cb)\s*\(/i', $ctx ) ) {
					return true;
				}
				if ( preg_match( '/sanitize_(?:text_field|textarea_field|email|title|key|file_name|hex_color|user)/i', $ctx ) ) {
					return true;
				}
				break;

			case 'webshell_markers':
				// Security plugins embed attack names inside WAF rule patterns.
				if ( preg_match( '/wfWAFRule|Wordfence|#\\^/i', substr( $content, max( 0, $offset - 120 ), 240 ) ) ) {
					return true;
				}
				break;

			case 'nested_decoders':
				// Slider/export codecs: gzuncompress(base64_decode($data)) without eval — RevSlider etc.
				$ctx = substr( $content, max( 0, $offset - 80 ), strlen( (string) $match ) + 200 );
				if ( preg_match( '/gz(?:en|de|uncompress)|json_decode|RevSlider|NOSONAR/i', $ctx )
					&& ! preg_match( '/\b(?:eval|assert|create_function)\s*\(/i', $ctx ) ) {
					return true;
				}
				if ( preg_match( '#wp-content/plugins/(?:revslider|js_composer|essential-grid)/#', $rel ) ) {
					return true;
				}
				break;

			case 'long_base64_blob':
				// Benign charset / alphabet tables (not base64 payloads).
				if ( preg_match( '/alphabet|charset|dictionary|keyspace/i', substr( $content, max( 0, $offset - 80 ), 160 ) ) ) {
					return true;
				}
				break;
		}

		return (bool) apply_filters( 'mvn_scan_false_positive', false, $sig_id, $rel, $content, $offset, $match );
	}

	/**
	 * Find every .htaccess under ABSPATH (fast walk).
	 */
	public static function find_all_htaccess() {
		$out   = array();
		$stack = array( rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) );
		$max   = 50000;
		while ( ! empty( $stack ) && count( $out ) < $max ) {
			$dir   = array_pop( $stack );
			$items = @scandir( $dir );
			if ( false === $items ) {
				continue;
			}
			foreach ( $items as $item ) {
				if ( '.' === $item || '..' === $item ) {
					continue;
				}
				$path = $dir . '/' . $item;
				if ( is_dir( $path ) ) {
					$rel = mvn_rel_path( $path );
					if ( mvn_is_skippable_dir( $rel ) ) {
						continue;
					}
					$stack[] = $path;
				} elseif ( '.htaccess' === $item || 'htaccess' === $item ) {
					$out[] = mvn_rel_path( $path );
				}
			}
		}
		return $out;
	}

	public static function get_state() {
		return mvn_state_read( self::STATE_KEY );
	}

	public static function get_issues() {
		$issues = MVN_Incidents::issues();
		if ( ! is_array( $issues ) ) {
			return array();
		}
		return self::sort_issues( $issues );
	}

	/**
	 * Count open issues grouped by action type.
	 *
	 * @return array<string,int>
	 */
	public static function count_by_action( $issues = null ) {
		if ( null === $issues ) {
			$issues = self::get_issues();
		}
		$counts = array(
			'total'              => 0,
			'fixable'            => 0,
			'safe_fixable'       => 0,
			'clean'              => 0,
			'delete_htaccess'    => 0,
			'quarantine_delete'  => 0,
			'quarantine'         => 0,
			'db_clean'           => 0,
			'db_delete_option'   => 0,
			'as_delete'          => 0,
			'core_repair'        => 0,
			'core_repair_file'   => 0,
			'delete_core_extra'  => 0,
			'db_review'          => 0,
			'repo_repair'        => 0,
			'manual_review'      => 0,
		);
		if ( ! is_array( $issues ) ) {
			return $counts;
		}
		foreach ( $issues as $issue ) {
			$counts['total']++;
			$action = isset( $issue['action'] ) ? $issue['action'] : '';
			$norm   = class_exists( 'MVN_Cleaner' ) ? MVN_Cleaner::normalized_action( $issue ) : $action;
			if ( isset( $counts[ $action ] ) ) {
				$counts[ $action ]++;
			} elseif ( isset( $counts[ $norm ] ) ) {
				$counts[ $norm ]++;
			}
			if ( ! in_array( $norm, array( 'core_repair', 'db_review', 'repo_repair', 'manual_review' ), true ) ) {
				$counts['fixable']++;
			}
			if ( class_exists( 'MVN_Cleaner' ) && MVN_Cleaner::is_safe_auto_fix( $issue ) ) {
				$counts['safe_fixable']++;
			}
		}
		return $counts;
	}

	public static function clear_issues() {
		MVN_Incidents::store_issues( array() );
	}

	/**
	 * Mark a finding as safe (ignore list) and remove from open issues.
	 *
	 * @param string $id       Issue id (md5 of rel|sig).
	 * @param bool   $permanent Ignore even if file content changes.
	 * @return true|WP_Error
	 */
	public static function ignore_issue( $id, $permanent = false ) {
		$id     = sanitize_text_field( $id );
		$issues = get_option( MVN_OPTION_ISSUES, array() );
		if ( ! is_array( $issues ) ) {
			$issues = array();
		}

		$found = null;
		$kept  = array();
		foreach ( $issues as $issue ) {
			if ( isset( $issue['id'] ) && $issue['id'] === $id ) {
				$found = $issue;
				continue;
			}
			$kept[] = $issue;
		}

		if ( ! $found ) {
			return new WP_Error( 'mvn_not_found', 'یافته یافت نشد.' );
		}

		$hash = '';
		if ( ! empty( $found['content_hash'] ) ) {
			$hash = $found['content_hash'];
		} elseif ( ! empty( $found['file_hash'] ) ) {
			$hash = $found['file_hash'];
		}

		MVN_Ignore_List::add(
			isset( $found['rel'] ) ? $found['rel'] : '',
			isset( $found['sig'] ) ? $found['sig'] : '',
			$hash,
			$permanent
		);

		MVN_Incidents::store_issues( self::sort_issues( $kept ) );
		MVN_Incidents::transition( $id, 'ignored', 'administrator', array( 'permanent' => (bool) $permanent ) );

		$rel = isset( $found['rel'] ) ? $found['rel'] : '';
		$is_db = ( ! empty( $found['source'] ) && 'db' === $found['source'] ) || ( 0 === strpos( $rel, 'db:' ) );
		if ( $rel && ! $is_db ) {
			$has_more = false;
			foreach ( $kept as $issue ) {
				if ( isset( $issue['rel'] ) && $issue['rel'] === $rel ) {
					$has_more = true;
					break;
				}
			}
			if ( ! $has_more ) {
				$abs = mvn_abs_path( $rel );
				if ( $abs && is_file( $abs ) ) {
					$mtime = @filemtime( $abs );
					$size  = @filesize( $abs );
					if ( false !== $mtime && false !== $size ) {
						MVN_File_Index::mark( $rel, true, $mtime, $size, (string) @hash_file( 'sha256', $abs ) );
						MVN_File_Index::flush();
					}
				}
			}
		}

		mvn_log( 'Issue ignored: ' . $id . ( $permanent ? ' (permanent)' : '' ) );
		return true;
	}

	/**
	 * Build UTF-8 CSV export for open scan issues.
	 *
	 * @param array $issues Issue list (defaults to stored issues).
	 * @return string
	 */
	public static function issues_to_csv( $issues = null ) {
		if ( null === $issues ) {
			$issues = self::get_issues();
		}
		if ( ! is_array( $issues ) ) {
			$issues = array();
		}

		$fh = fopen( 'php://temp', 'r+' );
		if ( false === $fh ) {
			return '';
		}

		fwrite( $fh, "\xEF\xBB\xBF" );
		fputcsv(
			$fh,
			array(
				'شناسه',
				'اطمینان٪',
				'برچسب اطمینان',
				'شدت',
				'منبع',
				'مسیر',
				'جدول',
				'ستون',
				'امضا',
				'نوع تهدید',
				'جزئیات',
				'اقدام',
				'نمونه کد',
				'MD5 مورد انتظار',
				'MD5 فعلی',
			)
		);

		foreach ( $issues as $iss ) {
			$severity = isset( $iss['severity'] ) ? $iss['severity'] : '';
			if ( 'critical' === $severity ) {
				$severity_label = 'بحرانی';
			} elseif ( 'warning' === $severity ) {
				$severity_label = 'هشدار';
			} else {
				$severity_label = 'اطلاع';
			}

			$actual_hash = '';
			if ( ! empty( $iss['actual_hash'] ) ) {
				$actual_hash = $iss['actual_hash'];
			} elseif ( ! empty( $iss['file_hash'] ) ) {
				$actual_hash = $iss['file_hash'];
			} elseif ( ! empty( $iss['content_hash'] ) ) {
				$actual_hash = $iss['content_hash'];
			}

			fputcsv(
				$fh,
				array(
					isset( $iss['id'] ) ? $iss['id'] : '',
					isset( $iss['confidence'] ) ? (int) $iss['confidence'] : '',
					isset( $iss['conf_label'] ) ? $iss['conf_label'] : '',
					$severity_label,
					isset( $iss['source'] ) ? $iss['source'] : 'file',
					isset( $iss['rel'] ) ? $iss['rel'] : '',
					isset( $iss['table'] ) ? $iss['table'] : '',
					isset( $iss['column'] ) ? $iss['column'] : '',
					isset( $iss['sig'] ) ? $iss['sig'] : '',
					isset( $iss['label'] ) ? $iss['label'] : '',
					isset( $iss['detail'] ) ? $iss['detail'] : '',
					isset( $iss['action'] ) ? $iss['action'] : '',
					isset( $iss['snippet'] ) ? $iss['snippet'] : '',
					isset( $iss['expected_hash'] ) ? $iss['expected_hash'] : '',
					$actual_hash,
				)
			);
		}

		rewind( $fh );
		$csv = stream_get_contents( $fh );
		fclose( $fh );
		return is_string( $csv ) ? $csv : '';
	}
}
