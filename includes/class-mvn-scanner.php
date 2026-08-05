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
		$scope = isset( $opts['scope'] ) ? $opts['scope'] : 'all';
		$deep  = ! empty( $opts['deep'] );

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
		$files = array_values( array_unique( $files ) );

		// Filter by extension / size.
		$scannable = mvn_scannable_extensions();
		$binary    = mvn_binary_extensions();
		$filtered  = array();
		foreach ( $files as $rel ) {
			if ( mvn_is_skippable_dir( dirname( $rel ) ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
			// Bare .htaccess has empty extension.
			$name = basename( $rel );
			if ( '.htaccess' === $name || 'htaccess' === $name ) {
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

		$state = array(
			'id'          => gmdate( 'YmdHis' ) . '-' . wp_generate_password( 6, false ),
			'started_at'  => gmdate( 'c' ),
			'updated_at'  => gmdate( 'c' ),
			'scope'       => $scope,
			'deep'        => $deep,
			'status'      => 'running',
			'total'       => count( $filtered ),
			'processed'   => 0,
			'cursor'      => 0,
			'files'       => $filtered,
			'issues'      => array(),
			'stats'       => array(
				'critical' => 0,
				'warning'  => 0,
				'info'     => 0,
				'htaccess' => 0,
				'php'      => 0,
				'js'       => 0,
			),
		);
		mvn_state_write( self::STATE_KEY, $state );
		update_option( MVN_OPTION_LASTSCAN, array( 'id' => $state['id'], 'started_at' => $state['started_at'] ), false );
		mvn_log( 'Scan started: ' . $state['id'] . ' files=' . $state['total'] );
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

		$sigs   = mvn_signatures();
		$start  = (int) $state['cursor'];
		$total  = (int) $state['total'];
		$end    = min( $start + self::CHUNK, $total );
		$files  = isset( $state['files'] ) ? $state['files'] : array();

		for ( $i = $start; $i < $end; $i++ ) {
			$rel = $files[ $i ];
			self::scan_one( $rel, $sigs, $state );
		}

		$state['cursor']     = $end;
		$state['processed']  = $end;
		$state['updated_at'] = gmdate( 'c' );

		if ( $end >= $total ) {
			$state['status']       = 'done';
			$state['finished_at']  = gmdate( 'c' );
			// Persist final issues to WP option for Fix page.
			update_option( MVN_OPTION_ISSUES, $state['issues'], false );
			update_option(
				MVN_OPTION_LASTSCAN,
				array(
					'id'          => $state['id'],
					'started_at'  => $state['started_at'],
					'finished_at' => $state['finished_at'],
					'total'       => $state['total'],
					'stats'       => $state['stats'],
					'issue_count' => count( $state['issues'] ),
				),
				false
			);
			mvn_log( 'Scan done: issues=' . count( $state['issues'] ) );
			// Free the huge files list from state (keep issues).
			$state['files'] = array();
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	/**
	 * Scan a single relative path and append findings to $state.
	 */
	private static function scan_one( $rel, $sigs, &$state ) {
		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return;
		}
		$size = @filesize( $abs );
		if ( false === $size || $size > 5 * 1024 * 1024 ) {
			// Skip >5MB to keep AJAX responsive.
			return;
		}

		$content = @file_get_contents( $abs );
		if ( false === $content || '' === $content ) {
			return;
		}

		$name = basename( $rel );
		$ext  = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
		$is_htaccess = ( '.htaccess' === $name || 'htaccess' === $name );
		$is_php      = in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'inc' ), true );
		$is_js       = ( 'js' === $ext );

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
					self::add_issue(
						$state,
						array(
							'rel'      => $rel,
							'sig'      => 'rogue_htaccess',
							'label'    => 'htaccess جعلی / مخرب',
							'severity' => 'critical',
							'detail'   => $reason,
							'action'   => 'delete_htaccess',
							'snippet'  => self::snippet( $content, 0, 180 ),
						)
					);
					$state['stats']['htaccess']++;
				}
			}
		}

		$scope_key = $is_htaccess ? 'htaccess' : ( $is_php ? 'php' : ( $is_js ? 'js' : 'any' ) );

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
			}
			if ( @preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$offset = isset( $m[0][1] ) ? (int) $m[0][1] : 0;
				$action = 'none' === $sig['clean'] ? 'quarantine' : 'clean';
				if ( $is_htaccess && 'none' === $sig['clean'] ) {
					$action = 'delete_htaccess';
				}
				self::add_issue(
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
					)
				);
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
			self::add_issue(
				$state,
				array(
					'rel'      => $rel,
					'sig'      => 'php_in_uploads',
					'label'    => 'فایل PHP داخل پوشه uploads',
					'severity' => 'critical',
					'detail'   => 'وجود PHP در uploads تقریباً همیشه نشانه بدافزار است.',
					'action'   => 'quarantine_delete',
					'snippet'  => self::snippet( $content, 0, 160 ),
				)
			);
			$state['stats']['critical']++;
		}
	}

	private static function add_issue( &$state, $issue ) {
		// Deduplicate by rel+sig.
		$key = $issue['rel'] . '|' . $issue['sig'];
		foreach ( $state['issues'] as $existing ) {
			if ( $existing['rel'] . '|' . $existing['sig'] === $key ) {
				return;
			}
		}
		$issue['id'] = md5( $key );
		$state['issues'][] = $issue;
	}

	private static function snippet( $content, $offset, $len ) {
		$start = max( 0, $offset - 40 );
		$chunk = substr( $content, $start, $len );
		$chunk = preg_replace( '/\s+/', ' ', $chunk );
		return mb_substr( $chunk, 0, $len );
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
		$issues = get_option( MVN_OPTION_ISSUES, array() );
		return is_array( $issues ) ? $issues : array();
	}

	public static function clear_issues() {
		update_option( MVN_OPTION_ISSUES, array(), false );
	}
}
