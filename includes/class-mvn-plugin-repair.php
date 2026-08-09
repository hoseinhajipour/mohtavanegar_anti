<?php
/**
 * Plugin repair — download fresh copies from WordPress.org and replace local plugin files.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Plugin_Repair {

	const STATE_KEY = 'plugin_repair';
	const CHUNK     = 30;

	/**
	 * Slugs / folders that must never be replaced (this antivirus plugin).
	 */
	private static function is_protected( $slug, $folder ) {
		$protected_slugs   = array( 'mohtavanegar-antivirus', 'mohtavanegar_anti', 'mohtavanegar-anti' );
		$protected_folders = array( 'mohtavanegar-antivirus', 'mohtavanegar_anti', 'mohtavanegar-anti' );
		$self_dir          = basename( dirname( MVN_PLUGIN_FILE ) );
		$protected_folders[] = $self_dir;
		return in_array( $slug, $protected_slugs, true ) || in_array( $folder, $protected_folders, true );
	}

	/**
	 * Build catalog with install status for the admin UI.
	 */
	public static function catalog_status() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$out       = array();

		foreach ( mvn_repo_plugins() as $item ) {
			$folder   = $item['folder'];
			$abs      = self::plugin_dir( $folder );
			$exists   = is_dir( $abs );
			$version  = '';
			$active   = false;
			$mainfile = '';

			foreach ( $installed as $file => $data ) {
				if ( 0 === strpos( $file, $folder . '/' ) ) {
					$version  = isset( $data['Version'] ) ? $data['Version'] : '';
					$mainfile = $file;
					$active   = is_plugin_active( $file );
					break;
				}
			}

			$file_count = 0;
			if ( $exists ) {
				$files = mvn_list_files( $abs, 500000 );
				$file_count = count( $files );
			}

			$out[] = array(
				'slug'        => $item['slug'],
				'name'        => $item['name'],
				'folder'      => $folder,
				'installed'   => $exists,
				'version'     => $version,
				'active'      => $active,
				'mainfile'    => $mainfile,
				'file_count'  => $file_count,
				'protected'   => self::is_protected( $item['slug'], $folder ),
				'download'    => self::download_url_for( $item['slug'] ),
			);
		}

		return $out;
	}

	private static function plugin_dir( $folder ) {
		return rtrim( WP_PLUGIN_DIR, '/\\' ) . DIRECTORY_SEPARATOR . $folder;
	}

	private static function download_url_for( $slug ) {
		return 'https://downloads.wordpress.org/plugin/' . rawurlencode( $slug ) . '.latest-stable.zip';
	}

	private static function backups_dir() {
		mvn_ensure_data_dirs();
		$dir = mvn_data_dir() . '/backups/plugins';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		return $dir;
	}

	private static function temp_zip_path( $slug ) {
		return mvn_data_dir() . '/state/plugin-' . sanitize_key( $slug ) . '.zip';
	}

	/**
	 * Start repair: download zip, backup old plugin, index zip entries.
	 *
	 * @param string $slug WordPress.org plugin slug.
	 * @return array|WP_Error
	 */
	public static function start( $slug ) {
		$lock = mvn_job_lock_acquire( 'filesystem_mutation', 1800 );
		if ( ! $lock ) {
			return new WP_Error( 'job_locked', 'یک عملیات اسکن/تعمیر دیگر در حال اجراست.' );
		}
		$item = mvn_repo_plugin_by_slug( $slug );
		if ( ! $item ) {
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'unknown_plugin', 'این پلاگین در لیست مخزن مجاز نیست.' );
		}
		if ( self::is_protected( $item['slug'], $item['folder'] ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'protected', 'این پلاگین محافظت‌شده است و قابل جایگزینی نیست.' );
		}
		if ( ! class_exists( 'ZipArchive' ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'no_zip', 'افزونه ZipArchive در PHP فعال نیست.' );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';

		@set_time_limit( 300 );

		$folder    = $item['folder'];
		$plugin_abs = self::plugin_dir( $folder );
		$zip_path  = self::temp_zip_path( $slug );

		// Download fresh copy from WordPress.org.
		mvn_log( "Plugin repair: downloading {$slug} from wordpress.org" );
		$download_url = self::download_url_for( $slug );
		$trusted = MVN_URL_Trust::validate( $download_url );
		if ( is_wp_error( $trusted ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return $trusted;
		}
		$tmp = download_url( $download_url, 300 );
		if ( is_wp_error( $tmp ) ) {
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'download_fail', 'دانلود از مخزن وردپرس ناموفق: ' . $tmp->get_error_message() );
		}

		if ( ! @rename( $tmp, $zip_path ) ) {
			if ( ! @copy( $tmp, $zip_path ) ) {
				@unlink( $tmp );
				mvn_job_lock_release( 'filesystem_mutation', $lock );
				return new WP_Error( 'save_fail', 'ذخیره فایل دانلودشده ناموفق بود.' );
			}
			@unlink( $tmp );
		}

		// Detect root folder inside the zip (usually matches slug/folder).
		$zip_root = self::detect_zip_root( $zip_path, $folder, $slug );
		if ( ! $zip_root ) {
			@unlink( $zip_path );
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'bad_zip', 'ساختار آرشیو دانلودشده نامعتبر است.' );
		}

		// Backup existing plugin folder before replacement.
		$backup_path = '';
		if ( is_dir( $plugin_abs ) ) {
			$backup = self::backup_plugin( $plugin_abs, $folder, $slug );
			if ( ! $backup ) {
				@unlink( $zip_path );
				mvn_job_lock_release( 'filesystem_mutation', $lock );
				return new WP_Error(
					'backup_fail',
					'پشتیبان‌گیری از نسخه فعلی پلاگین ناموفق بود. سطح دستریس wp-content/mvn-data/backups/plugins را بررسی کنید.'
				);
			}
			$backup_path = $backup['path'];
			mvn_log( "Plugin repair: backed up {$folder} ({$backup['type']}) -> {$backup_path}" );
		}

		// Extract into an isolated sibling; the live plugin is untouched until verification.
		$stage_abs = dirname( $plugin_abs ) . DIRECTORY_SEPARATOR . '.mvn-stage-' . sanitize_key( $folder ) . '-' . substr( $lock, 0, 8 );
		self::empty_directory( $stage_abs );
		if ( ! wp_mkdir_p( $stage_abs ) ) {
			@unlink( $zip_path );
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'stage_fail', 'ساخت staging تعمیر پلاگین ناموفق بود.' );
		}

		// Index zip entries for chunked extraction.
		$zip = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			@unlink( $zip_path );
			self::empty_directory( $stage_abs );
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'zip_open', 'باز کردن آرشیو دانلودشده ناموفق بود.' );
		}

		$prefix  = rtrim( $zip_root, '/' ) . '/';
		$entries = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$name = str_replace( '\\', '/', $stat['name'] );
			if ( '/' === substr( $name, -1 ) ) {
				continue; // directory
			}
			if ( 0 !== strpos( $name, $prefix ) ) {
				continue;
			}
			$rel = substr( $name, strlen( $prefix ) );
			if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
				continue;
			}
			$entries[] = array(
				'index' => $i,
				'rel'   => $rel,
			);
		}
		$zip->close();

		if ( empty( $entries ) ) {
			@unlink( $zip_path );
			self::empty_directory( $stage_abs );
			mvn_job_lock_release( 'filesystem_mutation', $lock );
			return new WP_Error( 'empty_zip', 'آرشیو دانلودشده فایل معتبری نداشت.' );
		}

		$state = array(
			'status'      => 'running',
			'phase'       => 'extract',
			'slug'        => $slug,
			'name'        => $item['name'],
			'folder'      => $folder,
			'zip_path'    => $zip_path,
			'zip_root'    => $zip_root,
			'stage_path'   => $stage_abs,
			'backup_path' => $backup_path,
			'lock_token'   => $lock,
			'started_at'  => gmdate( 'c' ),
			'total'       => count( $entries ),
			'cursor'      => 0,
			'written'     => 0,
			'skipped'     => 0,
			'errors'      => array(),
			'entries'     => $entries,
		);

		mvn_state_write( self::STATE_KEY, $state );
		mvn_log( "Plugin repair started: {$slug} files=" . $state['total'] );
		return $state;
	}

	/**
	 * Extract next chunk of files from the downloaded zip.
	 */
	public static function tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) || 'running' !== $state['status'] ) {
			return $state;
		}

		$zip_path = isset( $state['zip_path'] ) ? $state['zip_path'] : '';
		$folder   = isset( $state['folder'] ) ? $state['folder'] : '';
		if ( ! $zip_path || ! is_file( $zip_path ) || ! $folder ) {
			$state['status']   = 'error';
			$state['errors'][] = 'zip یا folder نامعتبر';
			mvn_job_lock_release( 'filesystem_mutation', isset( $state['lock_token'] ) ? $state['lock_token'] : '' );
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}

		$plugin_abs = self::plugin_dir( $folder );
		$stage_abs  = isset( $state['stage_path'] ) ? $state['stage_path'] : '';
		if ( ! $stage_abs || false === mvn_safe_write_path( $stage_abs ) ) {
			$state['status']   = 'error';
			$state['errors'][] = 'مسیر staging نامعتبر';
			mvn_job_lock_release( 'filesystem_mutation', isset( $state['lock_token'] ) ? $state['lock_token'] : '' );
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}
		$zip        = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			$state['status']   = 'error';
			$state['errors'][] = 'باز کردن zip ناموفق';
			mvn_job_lock_release( 'filesystem_mutation', isset( $state['lock_token'] ) ? $state['lock_token'] : '' );
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}

		$start   = (int) $state['cursor'];
		$total   = (int) $state['total'];
		$end     = min( $start + self::CHUNK, $total );
		$entries = isset( $state['entries'] ) ? $state['entries'] : array();

		for ( $i = $start; $i < $end; $i++ ) {
			$entry = $entries[ $i ];
			$rel   = $entry['rel'];
			$dest  = $stage_abs . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );

			$content = $zip->getFromIndex( $entry['index'] );
			if ( false === $content ) {
				$state['errors'][] = $rel . ': خواندن از zip ناموفق';
				continue;
			}

			if ( is_file( $dest ) && (string) @file_get_contents( $dest ) === $content ) {
				$state['skipped']++;
				continue;
			}

			$parent = dirname( $dest );
			if ( ! is_dir( $parent ) ) {
				wp_mkdir_p( $parent );
			}

			if ( ! mvn_atomic_write( $dest, $content, 0644 ) ) {
				$state['errors'][] = $rel . ': نوشتن ناموفق';
				continue;
			}
			@chmod( $dest, 0644 );
			$state['written']++;
		}

		$zip->close();
		$state['cursor']     = $end;
		$state['updated_at'] = gmdate( 'c' );

		if ( $end >= $total ) {
			$state['status'] = 'done';
			if ( ! empty( $state['errors'] ) ) {
				$state['status'] = 'error';
				self::empty_directory( $stage_abs );
			} else {
				$verified = self::verify_stage_checksums( $stage_abs, $state['slug'] );
				if ( is_wp_error( $verified ) ) {
					$state['status']   = 'error';
					$state['errors'][] = $verified->get_error_message();
					self::empty_directory( $stage_abs );
				}
			}
			if ( 'done' === $state['status'] ) {
				$rollback = dirname( $plugin_abs ) . DIRECTORY_SEPARATOR . '.mvn-rollback-' . sanitize_key( $folder ) . '-' . gmdate( 'YmdHis' );
				if ( is_dir( $plugin_abs ) && ! @rename( $plugin_abs, $rollback ) ) {
					$state['status']   = 'error';
					$state['errors'][] = 'جابجایی نسخه فعلی برای rollback ناموفق بود';
				} elseif ( ! @rename( $stage_abs, $plugin_abs ) ) {
					if ( is_dir( $rollback ) ) {
						@rename( $rollback, $plugin_abs );
					}
					$state['status']   = 'error';
					$state['errors'][] = 'atomic swap ناموفق بود؛ نسخه قبلی بازگردانده شد';
				} else {
					$state['rollback_path'] = is_dir( $rollback ) ? $rollback : '';
					mvn_invalidate_runtime_caches();
				}
			}
			$state['finished_at'] = gmdate( 'c' );
			$state['entries']     = array();
			@unlink( $zip_path );
			mvn_job_lock_release( 'filesystem_mutation', isset( $state['lock_token'] ) ? $state['lock_token'] : '' );
			mvn_log(
				'Plugin repair done: ' . $state['slug'] .
				' written=' . $state['written'] .
				' skipped=' . $state['skipped'] .
				' errors=' . count( $state['errors'] )
			);
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function get_state() {
		return mvn_state_read( self::STATE_KEY );
	}

	/**
	 * One-click rollback of the last completed directory swap.
	 *
	 * @return bool|WP_Error
	 */
	public static function rollback() {
		$state = self::get_state();
		if ( empty( $state['folder'] ) || empty( $state['rollback_path'] ) || ! is_dir( $state['rollback_path'] ) ) {
			return new WP_Error( 'no_rollback', 'نسخه rollback در دسترس نیست.' );
		}
		$lock = mvn_job_lock_acquire( 'filesystem_mutation', 300 );
		if ( ! $lock ) {
			return new WP_Error( 'job_locked', 'عملیات دیگری در حال اجراست.' );
		}
		$live   = self::plugin_dir( $state['folder'] );
		$failed = dirname( $live ) . DIRECTORY_SEPARATOR . '.mvn-failed-' . sanitize_key( $state['folder'] ) . '-' . gmdate( 'YmdHis' );
		$ok     = ( ! is_dir( $live ) || @rename( $live, $failed ) ) && @rename( $state['rollback_path'], $live );
		if ( ! $ok && is_dir( $failed ) && ! is_dir( $live ) ) {
			@rename( $failed, $live );
		}
		mvn_job_lock_release( 'filesystem_mutation', $lock );
		mvn_invalidate_runtime_caches();
		return $ok ? true : new WP_Error( 'rollback_fail', 'rollback پلاگین ناموفق بود.' );
	}

	private static function verify_stage_checksums( $stage, $slug ) {
		$version = '';
		foreach ( glob( $stage . '/*.php' ) ?: array() as $file ) {
			$head = (string) @file_get_contents( $file, false, null, 0, 8192 );
			if ( preg_match( '/^\s*\*?\s*Version:\s*(.+)$/mi', $head, $m ) ) {
				$version = trim( $m[1] );
				break;
			}
		}
		if ( '' === $version ) {
			return new WP_Error( 'package_version', 'نسخه پلاگین در staging قابل تشخیص نیست.' );
		}
		$url = sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) );
		$res = MVN_URL_Trust::get( $url, array( 'timeout' => 30, 'limit_response_size' => 16 * MB_IN_BYTES ) );
		$data = ! is_wp_error( $res ) ? json_decode( wp_remote_retrieve_body( $res ), true ) : null;
		if ( ! is_array( $data ) || empty( $data['files'] ) ) {
			return new WP_Error( 'package_checksums', 'checksum رسمی پلاگین در دسترس نیست؛ swap متوقف شد.' );
		}
		foreach ( $data['files'] as $rel => $expected ) {
			if ( false !== strpos( $rel, '..' ) ) {
				return new WP_Error( 'checksum_path', 'مسیر checksum نامعتبر است.' );
			}
			$expected = is_array( $expected ) ? reset( $expected ) : $expected;
			$file = $stage . '/' . str_replace( '\\', '/', $rel );
			if ( ! is_file( $file ) || ! hash_equals( strtolower( (string) $expected ), md5_file( $file ) ) ) {
				return new WP_Error( 'checksum_mismatch', 'checksum فایل پلاگین مطابقت ندارد: ' . $rel );
			}
		}
		return true;
	}

	/**
	 * Detect the top-level folder name inside a plugin zip.
	 */
	private static function detect_zip_root( $zip_path, $expected_folder, $slug ) {
		$zip = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			return false;
		}
		$candidates = array( $expected_folder, $slug );
		$found      = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$name = str_replace( '\\', '/', $stat['name'] );
			$parts = explode( '/', $name );
			if ( ! empty( $parts[0] ) ) {
				$found[ $parts[0] ] = true;
			}
		}
		$zip->close();

		foreach ( $candidates as $c ) {
			if ( isset( $found[ $c ] ) ) {
				return $c;
			}
		}
		// Fallback: first root folder found.
		$roots = array_keys( $found );
		return ! empty( $roots ) ? $roots[0] : false;
	}

	/**
	 * Backup plugin: try zip first, fall back to full directory copy (better for large plugins).
	 *
	 * @return array{type:string,path:string}|false
	 */
	private static function backup_plugin( $source_dir, $folder, $slug ) {
		$backups = self::backups_dir();
		if ( ! is_writable( $backups ) ) {
			mvn_log( "Plugin backup: backups dir not writable: {$backups}" );
			return false;
		}

		$stamp = gmdate( 'Ymd-His' );

		$zip_path = $backups . '/' . $slug . '-' . $stamp . '.zip';
		if ( self::zip_directory( $source_dir, $folder, $zip_path ) ) {
			return array( 'type' => 'zip', 'path' => $zip_path );
		}
		@unlink( $zip_path );

		// Fallback for huge plugins (Elementor etc.) when ZipArchive chokes.
		$dir_path = $backups . '/' . $slug . '-' . $stamp;
		if ( self::copy_directory( $source_dir, $dir_path ) ) {
			return array( 'type' => 'dir', 'path' => $dir_path );
		}

		return false;
	}

	/**
	 * Zip an entire plugin directory for backup.
	 */
	private static function zip_directory( $source_dir, $folder, $dest_zip ) {
		if ( ! class_exists( 'ZipArchive' ) || ! is_dir( $source_dir ) ) {
			return false;
		}

		$parent = dirname( $dest_zip );
		if ( ! is_dir( $parent ) ) {
			wp_mkdir_p( $parent );
		}

		$zip = new ZipArchive();
		$opened = $zip->open( $dest_zip, ZipArchive::CREATE | ZipArchive::OVERWRITE );
		if ( true !== $opened ) {
			mvn_log( "Plugin backup zip open failed: {$dest_zip} code={$opened}" );
			return false;
		}

		$source_dir = rtrim( str_replace( '\\', '/', $source_dir ), '/' );
		$files      = mvn_list_files_in( $source_dir, 500000 );
		$added      = 0;

		foreach ( $files as $rel ) {
			$abs = $source_dir . '/' . str_replace( '\\', '/', $rel );
			if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
				continue;
			}
			$entry = $folder . '/' . str_replace( '\\', '/', $rel );
			// Prefer addFromString — more reliable than addFile on shared hosting.
			$data = @file_get_contents( $abs );
			if ( false === $data ) {
				continue;
			}
			if ( $zip->addFromString( $entry, $data ) ) {
				$added++;
			}
		}

		$closed = $zip->close();
		if ( ! $closed || $added < 1 ) {
			mvn_log( "Plugin backup zip empty/failed: {$dest_zip} added={$added}" );
			@unlink( $dest_zip );
			return false;
		}

		return is_file( $dest_zip ) && filesize( $dest_zip ) > 0;
	}

	/**
	 * Recursive directory copy for backup fallback.
	 */
	private static function copy_directory( $source, $dest ) {
		$source = rtrim( str_replace( '\\', '/', $source ), '/' );
		if ( ! is_dir( $source ) ) {
			return false;
		}
		if ( is_dir( $dest ) ) {
			self::empty_directory( $dest );
			@rmdir( $dest );
		}
		if ( ! wp_mkdir_p( $dest ) ) {
			return false;
		}

		$files = mvn_list_files_in( $source, 500000 );
		if ( empty( $files ) ) {
			return false;
		}

		$copied = 0;
		foreach ( $files as $rel ) {
			$src = $source . '/' . str_replace( '\\', '/', $rel );
			$dst = $dest . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );
			if ( ! is_file( $src ) || ! is_readable( $src ) ) {
				continue;
			}
			$parent = dirname( $dst );
			if ( ! is_dir( $parent ) ) {
				wp_mkdir_p( $parent );
			}
			if ( @copy( $src, $dst ) ) {
				$copied++;
			}
		}

		return $copied > 0;
	}

	/**
	 * Delete all contents of a plugin directory (keep the folder).
	 */
	private static function empty_directory( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = @scandir( $dir );
		if ( false === $items ) {
			return;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . DIRECTORY_SEPARATOR . $item;
			if ( is_dir( $path ) ) {
				self::empty_directory( $path );
				@rmdir( $path );
			} else {
				@unlink( $path );
			}
		}
	}
}
