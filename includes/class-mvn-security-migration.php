<?php
/**
 * Security Architecture migration — relocate WordPress outside the public web root
 * and install a lightweight Security Gateway.
 *
 * Flow: preflight → backup → copy (chunked) → verify copy → switch → verify HTTP → cleanup
 * Prefer COPY → VERIFY → SWITCH → TEST → DELETE OLD over blind MOVE.
 *
 * Plugin self-protection: copying does not remove the live plugin. The switch of
 * wp-content is the last filesystem mutation in its tick; the response is sent
 * without requiring additional plugin files from disk.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Security_Migration {

	const OPTION       = 'mvn_security_migration_status';
	const STATE_FILE   = 'security_migration';
	const COPY_CHUNK   = 80;
	const LIST_DIR_CHUNK = 35;
	const TICK_SECONDS = 10;
	const BUSY_STATUSES = array( 'preflight', 'backup', 'listing', 'copying', 'verifying', 'switching', 'testing', 'cleanup', 'rollback' );

	/**
	 * Names exposed in the public root via symlink after migration.
	 *
	 * @return string[]
	 */
	public static function public_link_names() {
		return array(
			'wp-admin',
			'wp-includes',
			'wp-content',
			'wp-login.php',
			'wp-cron.php',
			'wp-comments-post.php',
			'wp-trackback.php',
			'wp-signup.php',
			'wp-activate.php',
			'wp-mail.php',
			'wp-links-opml.php',
			'xmlrpc.php',
		);
	}

	/**
	 * Root files that must leave the public web root after switch
	 * (already copied into the relocated core).
	 *
	 * @return string[]
	 */
	public static function public_evacuate_names() {
		return array(
			'wp-config.php',
			'wp-config-sample.php',
			'wp-load.php',
			'wp-settings.php',
			'wp-blog-header.php',
			'wp-config.php.bak',
			'readme.html',
			'license.txt',
			'licens.txt',
		);
	}

	/**
	 * @return array
	 */
	public static function defaults() {
		return array(
			'status'                 => 'not_started',
			'migration_id'           => '',
			'public_path'            => '',
			'core_path'              => '',
			'backup_dir'             => '',
			'started_at'             => '',
			'completed_at'           => '',
			'last_verification'      => '',
			'verification'           => array(),
			'error'                  => '',
			'copy_offset'            => 0,
			'copy_total'             => 0,
			'list_byte'              => 0,
			'lock_token'             => '',
			'remove_core_on_rollback'=> 1,
			'gateway_healthy'        => 0,
			'log_file'               => '',
		);
	}

	/**
	 * @return array
	 */
	public static function get_state() {
		$saved = get_option( self::OPTION, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return array_merge( self::defaults(), $saved );
	}

	/**
	 * @param array $state State.
	 */
	public static function save_state( array $state ) {
		$state = array_merge( self::defaults(), $state );
		update_option( self::OPTION, $state, false );
	}

	/**
	 * @return bool
	 */
	public static function is_completed() {
		$s = self::get_state();
		return 'completed' === $s['status'] && ! empty( $s['core_path'] ) && ! empty( $s['gateway_healthy'] );
	}

	/**
	 * @return bool
	 */
	public static function is_busy() {
		$s = self::get_state();
		return in_array( $s['status'], self::BUSY_STATUSES, true );
	}

	/**
	 * Propose a collision-safe core directory beside the public root.
	 *
	 * @return array{path:string,name:string}
	 */
	public static function propose_core_path() {
		$public = mvn_normalize_path( ABSPATH );
		$parent = mvn_normalize_path( dirname( $public ) );
		$seed   = home_url( '/' ) . '|' . $public;
		$hash   = substr( hash( 'sha256', $seed ), 0, 10 );
		$name   = 'mvn-wordpress-core-' . $hash;
		$path   = $parent . '/' . $name;
		$i      = 0;
		while ( is_dir( $path ) && $i < 20 ) {
			$i++;
			$path = $parent . '/' . $name . '-' . $i;
		}
		return array(
			'path' => $path,
			'name' => basename( $path ),
		);
	}

	/**
	 * Admin payload for the UI.
	 *
	 * @return array
	 */
	public static function admin_payload() {
		$state  = self::get_state();
		$doc    = MVN_Security_Validator::detect_document_root();
		// After migration ABSPATH is the relocated core; public root stays the document root.
		if ( $doc ) {
			$public = $doc;
		} elseif ( ! empty( $state['public_path'] ) ) {
			$public = mvn_normalize_path( $state['public_path'] );
		} else {
			$public = mvn_normalize_path( ABSPATH );
		}
		$prop   = self::propose_core_path();
		$logger_lines = array();
		if ( ! empty( $state['log_file'] ) && is_file( $state['log_file'] ) ) {
			$logger_lines = ( new MVN_Security_Logger( $state['log_file'] ) )->read_lines( 80 );
		}
		$completed = self::is_completed();
		return array(
			'state'            => $state,
			'completed'        => $completed,
			'busy'             => self::is_busy(),
			'public_path'      => $public,
			'document_root'    => $doc,
			'wordpress_path'   => $completed && ! empty( $state['core_path'] ) ? $state['core_path'] : mvn_normalize_path( ABSPATH ),
			'proposed_core'    => $completed && ! empty( $state['core_path'] ) ? $state['core_path'] : $prop['path'],
			'gateway_path'     => $public . '/index.php',
			'home_url'         => home_url( '/' ),
			'site_url'         => site_url( '/' ),
			'log_lines'        => $logger_lines,
		);
	}

	/**
	 * Start migration after a successful preflight.
	 * If a migration is already in progress, resume it instead of failing.
	 *
	 * @return array|WP_Error
	 */
	public static function start() {
		if ( self::is_completed() ) {
			return new WP_Error( 'already', 'Security Gateway از قبل فعال است.' );
		}
		if ( self::is_busy() ) {
			$state = self::get_state();
			// Long copy must not leave the site in maintenance after a dropped AJAX request.
			self::disable_maintenance( $state['public_path'], isset( $state['core_path'] ) ? $state['core_path'] : null );
			return array(
				'state'   => $state,
				'resumed' => 1,
				'message' => 'مهاجرت ناتمام پیدا شد — ادامه می‌یابد (' . $state['status'] . ').',
			);
		}

		$pre = MVN_Security_Validator::preflight();
		if ( empty( $pre['ok'] ) ) {
			return new WP_Error( 'preflight', 'پیش‌نیازها برقرار نیست.', $pre );
		}

		$lock = mvn_job_lock_acquire( 'filesystem_mutation', 7200 );
		if ( ! $lock ) {
			return new WP_Error( 'job_locked', 'یک عملیات اسکن/تعمیر دیگر در حال اجراست.' );
		}

		$migration_id = 'security-migration-' . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 4, false, false );
		$core         = self::propose_core_path();
		$public       = mvn_normalize_path( ABSPATH );
		$backup_root  = mvn_data_dir() . '/backups/' . $migration_id;
		mvn_ensure_data_dirs();
		if ( ! wp_mkdir_p( $backup_root ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'backup_dir', 'ساخت پوشه بک‌آپ ناموفق بود.' );
		}

		$log_file = $backup_root . '/migration.log';
		$logger   = new MVN_Security_Logger( $log_file );
		$logger->info( 'Preflight started' );
		$logger->info( 'Filesystem permissions verified' );
		$logger->info( 'Migration ID: ' . $migration_id );

		$state = array_merge(
			self::defaults(),
			array(
				'status'       => 'backup',
				'migration_id' => $migration_id,
				'public_path'  => $public,
				'core_path'    => $core['path'],
				'backup_dir'   => $backup_root,
				'started_at'   => gmdate( 'Y-m-d H:i:s' ),
				'lock_token'   => $lock,
				'log_file'     => $log_file,
			)
		);
		self::save_state( $state );
		mvn_state_write(
			self::STATE_FILE,
			array(
				'list_file' => '',
				'dir_queue' => array( '' ),
				'list_count'=> 0,
				'built'     => 0,
				'phase'     => 'backup',
			)
		);

		return array(
			'state'   => self::get_state(),
			'resumed' => 0,
			'message' => 'مهاجرت آغاز شد.',
		);
	}

	/**
	 * Abort an in-progress migration that has not switched the public root yet.
	 *
	 * @return array|WP_Error
	 */
	public static function abort() {
		$state = self::get_state();
		if ( ! self::is_busy() && 'failed' !== $state['status'] ) {
			return new WP_Error( 'not_busy', 'مهاجرت فعالی برای لغو وجود ندارد.' );
		}

		$switched = is_file( $state['public_path'] . '/index.php' )
			&& false !== strpos( (string) @file_get_contents( $state['public_path'] . '/index.php' ), 'MVN_SECURITY_GATEWAY' );
		if ( $switched || is_dir( $state['public_path'] . '/.mvn-pre-gateway-bak' ) ) {
			return new WP_Error( 'use_rollback', 'سوییچ انجام شده؛ از دکمه بازگردانی استفاده کنید.' );
		}

		$logger = new MVN_Security_Logger( ! empty( $state['log_file'] ) ? $state['log_file'] : ( mvn_data_dir() . '/logs/migration-abort.log' ) );
		$logger->warn( 'Migration aborted by admin' );

		self::disable_maintenance( $state['public_path'], isset( $state['core_path'] ) ? $state['core_path'] : null );

		if ( ! empty( $state['core_path'] ) && is_dir( $state['core_path'] ) && self::assert_migration_path( $state['core_path'], $state['public_path'] ) ) {
			MVN_Security_Rollback::force_remove( $state['core_path'] );
			$logger->info( 'Incomplete core copy removed' );
		}

		if ( ! empty( $state['lock_token'] ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $state['lock_token'] );
		} else {
			delete_option( 'mvn_lock_filesystem_mutation' );
		}

		self::save_state( self::defaults() );
		mvn_state_delete( self::STATE_FILE );

		return array(
			'state'   => self::get_state(),
			'message' => 'مهاجرت ناتمام لغو شد. می‌توانید دوباره شروع کنید.',
		);
	}

	/**
	 * Advance one migration tick.
	 *
	 * @return array|WP_Error
	 */
	public static function tick() {
		$state = self::get_state();
		if ( empty( $state['migration_id'] ) || 'not_started' === $state['status'] || 'completed' === $state['status'] ) {
			return new WP_Error( 'no_job', 'مهاجرت فعالی وجود ندارد.' );
		}
		if ( 'failed' === $state['status'] ) {
			return new WP_Error( 'failed', $state['error'] ? $state['error'] : 'مهاجرت قبلی ناموفق بوده است.' );
		}

		$logger = new MVN_Security_Logger( $state['log_file'] );

		try {
			switch ( $state['status'] ) {
				case 'backup':
					return self::tick_backup( $state, $logger );
				case 'listing':
					return self::tick_listing( $state, $logger );
				case 'copying':
					return self::tick_copy( $state, $logger );
				case 'verifying':
					return self::tick_verify_copy( $state, $logger );
				case 'switching':
					return self::tick_switch( $state, $logger );
				case 'testing':
					return self::tick_testing( $state, $logger );
				case 'cleanup':
					return self::tick_cleanup( $state, $logger );
				case 'rollback':
					return self::tick_rollback( $state, $logger );
				default:
					return new WP_Error( 'bad_status', 'وضعیت نامعتبر: ' . $state['status'] );
			}
		} catch ( Exception $e ) {
			return self::fail( $state, $logger, 'استثنا: ' . $e->getMessage(), true );
		}
	}

	/**
	 * Admin-triggered rollback after a completed (or failed-after-switch) migration.
	 *
	 * @return array|WP_Error
	 */
	public static function rollback() {
		$state = self::get_state();
		if ( empty( $state['backup_dir'] ) ) {
			return new WP_Error( 'no_backup', 'بک‌آپ برای بازگشت وجود ندارد.' );
		}
		$lock = mvn_job_lock_acquire( 'filesystem_mutation', 1800 );
		if ( ! $lock ) {
			return new WP_Error( 'job_locked', 'یک عملیات فایل دیگر در حال اجراست.' );
		}
		$logger = new MVN_Security_Logger( ! empty( $state['log_file'] ) ? $state['log_file'] : ( $state['backup_dir'] . '/migration.log' ) );
		$state['status'] = 'rollback';
		$state['lock_token'] = $lock;
		$state['remove_core_on_rollback'] = 1;
		self::save_state( $state );

		$result = MVN_Security_Rollback::run( $state, $logger );
		mvn_job_lock_release( 'filesystem_mutation', $lock );
		if ( is_wp_error( $result ) ) {
			$state['status'] = 'failed';
			$state['error']  = $result->get_error_message();
			$state['lock_token'] = '';
			self::save_state( $state );
			return $result;
		}

		$reset = self::defaults();
		$reset['status'] = 'not_started';
		$reset['error']  = '';
		self::save_state( $reset );
		mvn_state_delete( self::STATE_FILE );
		$logger->info( 'Rollback completed — architecture restored' );
		return array(
			'state'   => self::get_state(),
			'message' => 'معماری قبلی با موفقیت بازگردانده شد.',
		);
	}

	/**
	 * Re-run verification against a completed migration.
	 *
	 * @return array|WP_Error
	 */
	public static function reverify() {
		$state = self::get_state();
		if ( 'completed' !== $state['status'] || empty( $state['core_path'] ) ) {
			return new WP_Error( 'not_completed', 'مهاجرت تکمیل‌شده‌ای برای بررسی وجود ندارد.' );
		}
		$logger = new MVN_Security_Logger( $state['log_file'] );
		$ver    = MVN_Security_Validator::verify( $state['public_path'], $state['core_path'] );
		$state['verification'] = $ver;
		$state['last_verification'] = isset( $ver['at'] ) ? $ver['at'] : gmdate( 'Y-m-d H:i:s' );
		$state['gateway_healthy'] = ! empty( $ver['ok'] ) ? 1 : 0;
		self::save_state( $state );
		$logger->info( ! empty( $ver['ok'] ) ? 'Re-verification passed' : 'Re-verification failed' );
		return array(
			'state'        => self::get_state(),
			'verification' => $ver,
		);
	}

	/* ===================== ticks ===================== */

	/**
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_backup( array $state, MVN_Security_Logger $logger ) {
		$public = $state['public_path'];
		$backup = $state['backup_dir'];

		// Do NOT enable maintenance for the long copy phase — only during switch.
		$index = $public . '/index.php';
		$ht    = $public . '/.htaccess';
		if ( is_file( $index ) && ! @copy( $index, $backup . '/public-index.php' ) ) {
			return self::fail( $state, $logger, 'بک‌آپ index.php ناموفق بود.', true );
		}
		if ( is_file( $ht ) && ! @copy( $ht, $backup . '/public-htaccess' ) ) {
			return self::fail( $state, $logger, 'بک‌آپ .htaccess ناموفق بود.', true );
		}

		$meta = array(
			'abspath'        => ABSPATH,
			'wp_content_dir' => WP_CONTENT_DIR,
			'wp_content_url' => content_url(),
			'siteurl'        => site_url( '/' ),
			'home'           => home_url( '/' ),
			'wp_version'     => get_bloginfo( 'version' ),
			'php_version'    => PHP_VERSION,
			'db_name_set'    => defined( 'DB_NAME' ),
			'migration_id'   => $state['migration_id'],
			'plugin_version' => MVN_VERSION,
		);
		mvn_atomic_write( $backup . '/meta.json', wp_json_encode( $meta ), 0600 );

		$cfg = $public . '/wp-config.php';
		if ( is_file( $cfg ) ) {
			@copy( $cfg, $backup . '/wp-config.php.bak' );
			@chmod( $backup . '/wp-config.php.bak', 0600 );
		}

		$plugin_opt = get_option( MVN_OPTION_HARDENING, array() );
		mvn_atomic_write( $backup . '/plugin-hardening.json', wp_json_encode( $plugin_opt ), 0600 );

		$list_file = $backup . '/file-list.txt';
		@file_put_contents( $list_file, '' );

		mvn_state_write(
			self::STATE_FILE,
			array(
				'list_file'  => $list_file,
				'dir_queue'  => array( '' ),
				'list_count' => 0,
				'built'      => 0,
				'phase'      => 'listing',
			)
		);

		$logger->info( 'Backup completed' );
		$logger->info( 'File listing started (chunked)' );

		$state['status']      = 'listing';
		$state['copy_offset'] = 0;
		$state['copy_total']  = 0;
		$state['list_byte']   = 0;
		self::save_state( $state );

		return self::tick_response( $state, 'در حال فهرست‌سازی فایل‌ها…' );
	}

	/**
	 * Chunked directory walk — avoids one huge AJAX request timing out.
	 *
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_listing( array $state, MVN_Security_Logger $logger ) {
		$job = mvn_state_read( self::STATE_FILE, array() );
		$list_file = isset( $job['list_file'] ) ? (string) $job['list_file'] : '';
		$queue     = isset( $job['dir_queue'] ) && is_array( $job['dir_queue'] ) ? $job['dir_queue'] : array();
		$count     = isset( $job['list_count'] ) ? (int) $job['list_count'] : 0;

		if ( ! $list_file ) {
			return self::fail( $state, $logger, 'مسیر فهرست فایل نامعتبر است.', true );
		}

		$public = mvn_normalize_path( $state['public_path'] );
		$core   = mvn_normalize_path( $state['core_path'] );
		$skip_names = array( '.mvn-pre-gateway-bak', '.git', '.svn', 'node_modules', '.DS_Store' );

		$fh = @fopen( $list_file, 'ab' );
		if ( false === $fh ) {
			return self::fail( $state, $logger, 'باز کردن فهرست فایل ناموفق بود.', true );
		}

		$deadline = time() + self::TICK_SECONDS;
		$dirs_done = 0;

		while ( $queue && $dirs_done < self::LIST_DIR_CHUNK && time() < $deadline ) {
			$rel_dir = array_shift( $queue );
			$rel_dir = is_string( $rel_dir ) ? str_replace( '\\', '/', $rel_dir ) : '';
			if ( false !== strpos( $rel_dir, '..' ) ) {
				$dirs_done++;
				continue;
			}
			$abs_dir = '' === $rel_dir ? $public : ( $public . '/' . $rel_dir );
			if ( ! is_dir( $abs_dir ) ) {
				$dirs_done++;
				continue;
			}

			$entries = @scandir( $abs_dir );
			if ( ! is_array( $entries ) ) {
				$dirs_done++;
				continue;
			}

			foreach ( $entries as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				if ( in_array( $name, $skip_names, true ) ) {
					continue;
				}
				$rel = '' === $rel_dir ? $name : ( $rel_dir . '/' . $name );
				if ( false !== strpos( $rel, '..' ) || false !== strpos( $rel, "\n" ) ) {
					continue;
				}
				if ( preg_match( '#^wp-content/mvn-data/backups/security-migration-#', $rel ) ) {
					continue;
				}
				$abs = $public . '/' . $rel;
				if ( $core && 0 === strpos( mvn_normalize_path( $abs ), $core . '/' ) ) {
					continue;
				}
				if ( is_dir( $abs ) && ! is_link( $abs ) ) {
					$queue[] = $rel;
					continue;
				}
				if ( is_file( $abs ) || is_link( $abs ) ) {
					fwrite( $fh, $rel . "\n" );
					$count++;
				}
			}
			$dirs_done++;
		}
		fclose( $fh );

		mvn_state_write(
			self::STATE_FILE,
			array(
				'list_file'  => $list_file,
				'dir_queue'  => array_values( $queue ),
				'list_count' => $count,
				'built'      => empty( $queue ) ? 1 : 0,
				'phase'      => empty( $queue ) ? 'copying' : 'listing',
			)
		);

		if ( ! empty( $queue ) ) {
			$state['copy_total'] = $count;
			self::save_state( $state );
			return self::tick_response(
				$state,
				sprintf( 'فهرست‌سازی… %d فایل · %d پوشه باقی‌مانده', $count, count( $queue ) )
			);
		}

		$logger->info( 'File list built: ' . $count . ' files' );
		$state['status']      = 'copying';
		$state['copy_offset'] = 0;
		$state['copy_total']  = $count;
		$state['list_byte']   = 0;
		self::save_state( $state );

		return self::tick_response( $state, 'در حال کپی فایل‌ها…' );
	}

	/**
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_copy( array $state, MVN_Security_Logger $logger ) {
		$job       = mvn_state_read( self::STATE_FILE, array() );
		$list_file = isset( $job['list_file'] ) ? (string) $job['list_file'] : '';
		if ( ! $list_file || ! is_file( $list_file ) ) {
			return self::fail( $state, $logger, 'فهرست فایل‌های کپی پیدا نشد.', true );
		}

		$public = $state['public_path'];
		$core   = $state['core_path'];
		if ( ! is_dir( $core ) && ! wp_mkdir_p( $core ) ) {
			return self::fail( $state, $logger, 'ساخت پوشه مقصد ناموفق بود: ' . $core, true );
		}
		if ( ! self::assert_migration_path( $core, $public ) ) {
			return self::fail( $state, $logger, 'مسیر مقصد خارج از محدوده مجاز است.', true );
		}

		$offset    = (int) $state['copy_offset'];
		$total     = (int) $state['copy_total'];
		$list_byte = isset( $state['list_byte'] ) ? (int) $state['list_byte'] : 0;
		$deadline  = time() + self::TICK_SECONDS;

		$fh = @fopen( $list_file, 'rb' );
		if ( false === $fh ) {
			return self::fail( $state, $logger, 'خواندن فهرست فایل ناموفق بود.', true );
		}
		if ( $list_byte > 0 ) {
			fseek( $fh, $list_byte );
		} elseif ( $offset > 0 ) {
			// Resume legacy jobs that only stored a line offset.
			$skipped = 0;
			while ( $skipped < $offset && ! feof( $fh ) ) {
				if ( false === fgets( $fh ) ) {
					break;
				}
				$skipped++;
			}
			$list_byte = (int) ftell( $fh );
		}

		$copied = 0;
		while ( $copied < self::COPY_CHUNK && time() < $deadline && ! feof( $fh ) ) {
			$line = fgets( $fh );
			if ( false === $line ) {
				break;
			}
			$rel = trim( $line );
			$offset++;
			if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
				continue;
			}
			$src = $public . '/' . $rel;
			$dst = $core . '/' . $rel;
			if ( ! is_file( $src ) && ! is_link( $src ) ) {
				$copied++;
				continue;
			}
			$dir = dirname( $dst );
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				fclose( $fh );
				return self::fail( $state, $logger, 'ساخت پوشه ناموفق: ' . $rel, true );
			}
			if ( ! @copy( $src, $dst ) ) {
				fclose( $fh );
				return self::fail( $state, $logger, 'کپی ناموفق: ' . $rel, true );
			}
			$copied++;
		}
		$new_byte = ftell( $fh );
		$eof      = feof( $fh );
		fclose( $fh );

		$state['copy_offset'] = $offset;
		$state['copy_total']  = $total;
		$state['list_byte']   = (int) $new_byte;

		if ( $eof || ( $total > 0 && $offset >= $total ) ) {
			$logger->info( 'WordPress files copied' );
			$state['status'] = 'verifying';
			self::save_state( $state );
			return self::tick_response( $state, 'در حال تأیید کپی…' );
		}

		self::save_state( $state );
		return self::tick_response(
			$state,
			sprintf( 'کپی فایل‌ها %d / %d', min( $offset, max( $total, $offset ) ), max( $total, $offset ) )
		);
	}

	/**
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_verify_copy( array $state, MVN_Security_Logger $logger ) {
		$core   = $state['core_path'];
		$public = $state['public_path'];
		$must   = array(
			'wp-load.php',
			'wp-blog-header.php',
			'wp-settings.php',
			'wp-login.php',
			'wp-admin/index.php',
			'wp-includes/version.php',
			'wp-content/plugins',
		);
		foreach ( $must as $rel ) {
			$path = $core . '/' . $rel;
			if ( ! file_exists( $path ) ) {
				return self::fail( $state, $logger, 'کپی ناقص است؛ یافت نشد: ' . $rel, true );
			}
		}
		if ( is_file( $public . '/wp-config.php' ) && ! is_file( $core . '/wp-config.php' ) ) {
			return self::fail( $state, $logger, 'wp-config.php در مقصد کپی نشده است.', true );
		}

		// Spot-check: compare sizes for a sample of files.
		$job       = mvn_state_read( self::STATE_FILE, array() );
		$list_file = isset( $job['list_file'] ) ? (string) $job['list_file'] : '';
		$sample    = $list_file ? self::read_list_slice( $list_file, 0, 25 ) : array();
		foreach ( $sample as $rel ) {
			$a = $public . '/' . $rel;
			$b = $core . '/' . $rel;
			if ( is_file( $a ) && is_file( $b ) && (int) filesize( $a ) !== (int) filesize( $b ) ) {
				return self::fail( $state, $logger, 'عدم تطابق اندازه فایل: ' . $rel, true );
			}
		}

		$logger->info( 'wp-config.php verified' );
		$logger->info( 'Copy verification passed' );
		$state['status'] = 'switching';
		self::save_state( $state );
		return self::tick_response( $state, 'در حال سوییچ به Gateway…' );
	}

	/**
	 * Switch public root to gateway + symlinks. wp-content is last.
	 *
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_switch( array $state, MVN_Security_Logger $logger ) {
		$public = $state['public_path'];
		$core   = $state['core_path'];
		$bak    = $public . '/.mvn-pre-gateway-bak';

		self::enable_maintenance( $public );

		if ( ! is_dir( $bak ) && ! wp_mkdir_p( $bak ) ) {
			return self::fail( $state, $logger, 'ساخت پوشه بک‌آپ سوییچ ناموفق بود.', true );
		}

		// Write rules + gateway + htaccess into core / staging first.
		$rules = MVN_Security_Gateway::generate_rules_php();
		if ( false === @file_put_contents( $core . '/mvn-gateway-rules.php', $rules ) ) {
			return self::fail( $state, $logger, 'نوشتن فایل قوانین Gateway ناموفق بود.', true );
		}
		@chmod( $core . '/mvn-gateway-rules.php', 0644 );

		$uploads = $core . '/wp-content/uploads';
		if ( is_dir( $uploads ) ) {
			$uht = MVN_Security_Gateway::uploads_htaccess();
			@file_put_contents( $uploads . '/.htaccess', $uht );
		}

		$gateway_php = MVN_Security_Gateway::generate_gateway_php( $core );
		$htaccess    = MVN_Security_Gateway::generate_htaccess();
		@file_put_contents( $state['backup_dir'] . '/new-index.php', $gateway_php );
		@file_put_contents( $state['backup_dir'] . '/new-htaccess', $htaccess );

		$links = self::public_link_names();
		// Switch non-content links first; wp-content last (plugin self-protection).
		usort(
			$links,
			static function ( $a, $b ) {
				if ( 'wp-content' === $a ) {
					return 1;
				}
				if ( 'wp-content' === $b ) {
					return -1;
				}
				return 0;
			}
		);

		foreach ( $links as $name ) {
			$src_public = $public . '/' . $name;
			$dst_core   = $core . '/' . $name;
			$bak_path   = $bak . '/' . $name;

			if ( ! file_exists( $dst_core ) && ! is_link( $dst_core ) ) {
				// Optional root files (xmlrpc etc.) may be absent.
				continue;
			}

			// Already a correct symlink?
			if ( is_link( $src_public ) ) {
				$current = @readlink( $src_public );
				if ( $current && MVN_Security_Validator::paths_equal( mvn_normalize_path( $current ), mvn_normalize_path( $dst_core ) ) ) {
					continue;
				}
				@unlink( $src_public );
			}

			if ( file_exists( $src_public ) || is_link( $src_public ) ) {
				if ( file_exists( $bak_path ) || is_link( $bak_path ) ) {
					MVN_Security_Rollback::force_remove( $bak_path );
				}
				if ( ! @rename( $src_public, $bak_path ) ) {
					return self::fail( $state, $logger, 'جابه‌جایی به بک‌آپ سوییچ ناموفق: ' . $name, true );
				}
			}

			if ( ! @symlink( $dst_core, $src_public ) ) {
				// Attempt rollback of this item.
				if ( file_exists( $bak_path ) ) {
					@rename( $bak_path, $src_public );
				}
				return self::fail( $state, $logger, 'ساخت symlink ناموفق: ' . $name, true );
			}
		}

		// Move secrets / bootstrap leftovers out of the public root (copies already exist in core).
		foreach ( self::public_evacuate_names() as $name ) {
			$src_public = $public . '/' . $name;
			if ( ! file_exists( $src_public ) && ! is_link( $src_public ) ) {
				continue;
			}
			$bak_path = $bak . '/' . $name;
			if ( file_exists( $bak_path ) || is_link( $bak_path ) ) {
				MVN_Security_Rollback::force_remove( $bak_path );
			}
			if ( is_link( $src_public ) ) {
				@unlink( $src_public );
				continue;
			}
			if ( ! @rename( $src_public, $bak_path ) ) {
				// Last resort: unlink only when core already has the file.
				if ( is_file( $core . '/' . $name ) && @unlink( $src_public ) ) {
					$logger->warn( 'Removed public leftover after failed rename: ' . $name );
					continue;
				}
				return self::fail( $state, $logger, 'انتقال فایل حساس از ریشه وب ناموفق: ' . $name, true );
			}
			$logger->info( 'Evacuated from public root: ' . $name );
		}

		// Install gateway index + htaccess (after links so admin assets resolve).
		$tmp_index = $public . '/.mvn-index-new.php';
		$tmp_ht    = $public . '/.mvn-htaccess-new';
		if ( false === @file_put_contents( $tmp_index, $gateway_php ) ) {
			return self::fail( $state, $logger, 'نوشتن موقت Gateway ناموفق بود.', true );
		}
		if ( false === @file_put_contents( $tmp_ht, $htaccess ) ) {
			@unlink( $tmp_index );
			return self::fail( $state, $logger, 'نوشتن موقت .htaccess ناموفق بود.', true );
		}

		$old_index = $public . '/index.php';
		if ( is_file( $old_index ) ) {
			@rename( $old_index, $bak . '/index.php.switched' );
		}
		if ( ! @rename( $tmp_index, $old_index ) ) {
			@copy( $tmp_index, $old_index );
			@unlink( $tmp_index );
		}

		$old_ht = $public . '/.htaccess';
		if ( is_file( $old_ht ) ) {
			@rename( $old_ht, $bak . '/htaccess.switched' );
		}
		if ( ! @rename( $tmp_ht, $old_ht ) ) {
			@copy( $tmp_ht, $old_ht );
			@unlink( $tmp_ht );
		}

		$logger->info( 'Gateway created' );
		$logger->info( '.htaccess created' );

		self::disable_maintenance( $public, $core );

		$state['status'] = 'testing';
		$state['remove_core_on_rollback'] = 0; // public is switched; keep core for rollback target via symlinks restore
		self::save_state( $state );

		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $old_index, true );
		}

		return self::tick_response( $state, 'در حال آزمون صحت…' );
	}

	/**
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_testing( array $state, MVN_Security_Logger $logger ) {
		$ver = MVN_Security_Validator::verify( $state['public_path'], $state['core_path'] );
		$state['verification'] = $ver;
		$state['last_verification'] = isset( $ver['at'] ) ? $ver['at'] : gmdate( 'Y-m-d H:i:s' );

		$failed_critical = array();
		$failed_soft     = array();
		foreach ( $ver['tests'] as $t ) {
			if ( ! empty( $t['ok'] ) ) {
				$logger->info( $t['label'] . ' passed' );
				continue;
			}
			$line = $t['label'] . ' failed: ' . $t['detail'];
			if ( ! empty( $t['critical'] ) ) {
				$logger->error( $line );
				$failed_critical[] = $t['label'];
			} else {
				$logger->warn( $line );
				$failed_soft[] = $t['label'];
			}
		}

		if ( ! empty( $failed_critical ) || empty( $ver['ok'] ) ) {
			$logger->error( 'Critical verification failed — starting automatic rollback' );
			$state['status'] = 'rollback';
			$state['error']  = 'آزمون‌های حیاتی پس از مهاجرت ناموفق بود: ' . implode( '، ', $failed_critical );
			$state['remove_core_on_rollback'] = 1;
			self::save_state( $state );
			return self::tick_rollback( $state, $logger );
		}

		if ( $failed_soft ) {
			$logger->warn( 'Soft verification warnings (kept migration): ' . implode( ', ', $failed_soft ) );
		}

		$state['gateway_healthy'] = 1;
		$state['status'] = 'cleanup';
		self::save_state( $state );
		$logger->info( 'All critical verification tests passed' );
		return self::tick_response( $state, $failed_soft ? 'آزمون حیاتی OK — در حال پاکسازی…' : 'در حال پاکسازی…' );
	}

	/**
	 * Remove pre-gateway bak after successful verification. Keep core; leave
	 * duplicate old trees deleted. Do not delete migration backup.
	 *
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_cleanup( array $state, MVN_Security_Logger $logger ) {
		$bak = $state['public_path'] . '/.mvn-pre-gateway-bak';
		if ( is_dir( $bak ) ) {
			MVN_Security_Rollback::force_remove( $bak );
			$logger->info( 'Pre-gateway backup removed after successful verification' );
		}

		// Drop large file list from state file to save space.
		mvn_state_write(
			self::STATE_FILE,
			array(
				'files' => array(),
				'built' => 1,
				'phase' => 'completed',
			)
		);

		self::disable_maintenance( $state['public_path'], $state['core_path'] );

		if ( ! empty( $state['lock_token'] ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $state['lock_token'] );
		}

		$state['status']       = 'completed';
		$state['completed_at'] = gmdate( 'Y-m-d H:i:s' );
		$state['lock_token']   = '';
		$state['error']        = '';
		$state['gateway_healthy'] = 1;
		self::save_state( $state );
		$logger->info( 'Migration completed' );

		return self::tick_response( $state, 'مهاجرت با موفقیت تمام شد.', true );
	}

	/**
	 * @param array               $state  State.
	 * @param MVN_Security_Logger $logger Logger.
	 * @return array|WP_Error
	 */
	private static function tick_rollback( array $state, MVN_Security_Logger $logger ) {
		$result = MVN_Security_Rollback::run( $state, $logger );
		if ( ! empty( $state['lock_token'] ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $state['lock_token'] );
		}
		if ( is_wp_error( $result ) ) {
			$state['status'] = 'failed';
			$state['error']  = $result->get_error_message();
			$state['lock_token'] = '';
			self::save_state( $state );
			self::disable_maintenance( $state['public_path'], isset( $state['core_path'] ) ? $state['core_path'] : null );
			return $result;
		}

		$error = ! empty( $state['error'] ) ? $state['error'] : 'مهاجرت ناموفق بود و بازگردانی انجام شد.';
		$failed = self::defaults();
		$failed['status'] = 'failed';
		$failed['error']  = $error;
		$failed['migration_id'] = $state['migration_id'];
		$failed['backup_dir']   = $state['backup_dir'];
		$failed['log_file']     = $state['log_file'];
		$failed['started_at']   = $state['started_at'];
		self::save_state( $failed );
		mvn_state_delete( self::STATE_FILE );
		$logger->error( 'Migration failed and was rolled back' );

		return new WP_Error( 'rolled_back', $error, array( 'state' => self::get_state() ) );
	}

	/* ===================== helpers ===================== */

	/**
	 * @param array               $state   State.
	 * @param MVN_Security_Logger $logger  Logger.
	 * @param string              $message Error.
	 * @param bool                $rollback Whether to attempt rollback.
	 * @return WP_Error
	 */
	private static function fail( array $state, MVN_Security_Logger $logger, $message, $rollback ) {
		$logger->error( $message );
		self::disable_maintenance( $state['public_path'], isset( $state['core_path'] ) ? $state['core_path'] : null );

		$switched = is_file( $state['public_path'] . '/index.php' )
			&& false !== strpos( (string) @file_get_contents( $state['public_path'] . '/index.php' ), 'MVN_SECURITY_GATEWAY' );

		if ( $rollback && ( $switched || is_dir( $state['public_path'] . '/.mvn-pre-gateway-bak' ) ) ) {
			$state['status'] = 'rollback';
			$state['error']  = $message;
			$state['remove_core_on_rollback'] = 1;
			self::save_state( $state );
			return self::tick_rollback( $state, $logger );
		}

		// Pre-switch failure: remove incomplete core copy.
		if ( ! empty( $state['core_path'] ) && is_dir( $state['core_path'] ) && ! $switched ) {
			MVN_Security_Rollback::force_remove( $state['core_path'] );
			$logger->info( 'Incomplete core copy removed' );
		}

		if ( ! empty( $state['lock_token'] ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $state['lock_token'] );
		}

		$failed = self::defaults();
		$failed['status'] = 'failed';
		$failed['error']  = $message;
		$failed['migration_id'] = isset( $state['migration_id'] ) ? $state['migration_id'] : '';
		$failed['backup_dir']   = isset( $state['backup_dir'] ) ? $state['backup_dir'] : '';
		$failed['log_file']     = isset( $state['log_file'] ) ? $state['log_file'] : '';
		$failed['started_at']   = isset( $state['started_at'] ) ? $state['started_at'] : '';
		self::save_state( $failed );
		mvn_state_delete( self::STATE_FILE );

		return new WP_Error( 'migration_failed', $message, array( 'state' => self::get_state() ) );
	}

	/**
	 * @param array  $state   State.
	 * @param string $message Message.
	 * @param bool   $done    Done flag.
	 * @return array
	 */
	private static function tick_response( array $state, $message, $done = false ) {
		$fresh = self::get_state();
		return array(
			'done'    => (bool) $done,
			'message' => $message,
			'state'   => $fresh,
			'progress'=> array(
				'status' => $fresh['status'],
				'offset' => (int) $fresh['copy_offset'],
				'total'  => (int) $fresh['copy_total'],
				'phase'  => $fresh['status'],
			),
		);
	}

	/**
	 * Build relative file list under public root into a line-delimited file.
	 *
	 * @param string $public    Public path.
	 * @param string $core      Destination core (excluded if nested).
	 * @param string $list_file Destination list path.
	 * @return int|false Count or false.
	 */
	private static function build_file_list_to( $public, $core, $list_file ) {
		$public = mvn_normalize_path( $public );
		$core   = mvn_normalize_path( $core );
		$skip_names = array(
			'.mvn-pre-gateway-bak',
			'.git',
			'.svn',
			'node_modules',
			'.DS_Store',
		);
		$fh = @fopen( $list_file, 'wb' );
		if ( false === $fh ) {
			return false;
		}
		$count = 0;
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $public, FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $it as $file ) {
				/** @var SplFileInfo $file */
				if ( ! $file->isFile() && ! $file->isLink() ) {
					continue;
				}
				$abs = mvn_normalize_path( $file->getPathname() );
				if ( 0 !== strpos( $abs, $public . '/' ) && $abs !== $public ) {
					continue;
				}
				$rel = ltrim( substr( $abs, strlen( $public ) ), '/' );
				if ( '' === $rel || false !== strpos( $rel, '..' ) || false !== strpos( $rel, "\n" ) ) {
					continue;
				}
				$parts = explode( '/', $rel );
				if ( array_intersect( $parts, $skip_names ) ) {
					continue;
				}
				if ( $core && 0 === strpos( $abs, $core . '/' ) ) {
					continue;
				}
				if ( preg_match( '#^wp-content/mvn-data/backups/security-migration-#', $rel ) ) {
					continue;
				}
				fwrite( $fh, $rel . "\n" );
				$count++;
			}
		} catch ( Exception $e ) {
			fclose( $fh );
			return false;
		}
		fclose( $fh );
		return $count;
	}

	/**
	 * Read a slice of the line-delimited file list.
	 *
	 * @param string $list_file List path.
	 * @param int    $offset    Start line.
	 * @param int    $limit     Max lines.
	 * @return string[]
	 */
	private static function read_list_slice( $list_file, $offset, $limit ) {
		$out = array();
		$fh  = @fopen( $list_file, 'rb' );
		if ( false === $fh ) {
			return $out;
		}
		$i = 0;
		while ( ! feof( $fh ) ) {
			$line = fgets( $fh );
			if ( false === $line ) {
				break;
			}
			if ( $i++ < $offset ) {
				continue;
			}
			$rel = trim( $line );
			if ( '' !== $rel && false === strpos( $rel, '..' ) ) {
				$out[] = $rel;
			}
			if ( count( $out ) >= $limit ) {
				break;
			}
		}
		fclose( $fh );
		return $out;
	}

	/**
	 * Ensure destination is a direct child of the public parent (no traversal).
	 *
	 * @param string $core   Core path.
	 * @param string $public Public path.
	 * @return bool
	 */
	private static function assert_migration_path( $core, $public ) {
		$core   = mvn_normalize_path( $core );
		$public = mvn_normalize_path( $public );
		$parent = mvn_normalize_path( dirname( $public ) );
		if ( '' === $core || false !== strpos( $core, "\0" ) ) {
			return false;
		}
		if ( ! mvn_path_is_within( $core, $parent ) ) {
			return false;
		}
		if ( mvn_path_is_within( $core, $public ) ) {
			return false;
		}
		$name = basename( $core );
		if ( ! preg_match( '/^mvn-wordpress-core-[a-f0-9]+(-\d+)?$/', $name ) ) {
			return false;
		}
		return true;
	}

	/**
	 * @param string $public Public path.
	 */
	private static function enable_maintenance( $public ) {
		$file = trailingslashit( $public ) . '.maintenance';
		$data = '<?php $upgrading = ' . time() . ";\n";
		@file_put_contents( $file, $data );
	}

	/**
	 * @param string      $public Public.
	 * @param string|null $core   Core.
	 */
	private static function disable_maintenance( $public, $core = null ) {
		MVN_Security_Rollback::disable_maintenance( $public, $core );
	}
}
