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
		$item = mvn_repo_plugin_by_slug( $slug );
		if ( ! $item ) {
			return new WP_Error( 'unknown_plugin', 'این پلاگین در لیست مخزن مجاز نیست.' );
		}
		if ( self::is_protected( $item['slug'], $item['folder'] ) ) {
			return new WP_Error( 'protected', 'این پلاگین محافظت‌شده است و قابل جایگزینی نیست.' );
		}
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error( 'no_zip', 'افزونه ZipArchive در PHP فعال نیست.' );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';

		@set_time_limit( 300 );

		$folder    = $item['folder'];
		$plugin_abs = self::plugin_dir( $folder );
		$zip_path  = self::temp_zip_path( $slug );

		// Download fresh copy from WordPress.org.
		mvn_log( "Plugin repair: downloading {$slug} from wordpress.org" );
		$tmp = download_url( self::download_url_for( $slug ), 300 );
		if ( is_wp_error( $tmp ) ) {
			return new WP_Error( 'download_fail', 'دانلود از مخزن وردپرس ناموفق: ' . $tmp->get_error_message() );
		}

		if ( ! @rename( $tmp, $zip_path ) ) {
			if ( ! @copy( $tmp, $zip_path ) ) {
				@unlink( $tmp );
				return new WP_Error( 'save_fail', 'ذخیره فایل دانلودشده ناموفق بود.' );
			}
			@unlink( $tmp );
		}

		// Detect root folder inside the zip (usually matches slug/folder).
		$zip_root = self::detect_zip_root( $zip_path, $folder, $slug );
		if ( ! $zip_root ) {
			@unlink( $zip_path );
			return new WP_Error( 'bad_zip', 'ساختار آرشیو دانلودشده نامعتبر است.' );
		}

		// Backup existing plugin folder before replacement.
		$backup_path = '';
		if ( is_dir( $plugin_abs ) ) {
			$backup = self::backup_plugin( $plugin_abs, $folder, $slug );
			if ( ! $backup ) {
				@unlink( $zip_path );
				return new WP_Error(
					'backup_fail',
					'پشتیبان‌گیری از نسخه فعلی پلاگین ناموفق بود. سطح دستریس wp-content/mvn-data/backups/plugins را بررسی کنید.'
				);
			}
			$backup_path = $backup['path'];
			mvn_log( "Plugin repair: backed up {$folder} ({$backup['type']}) -> {$backup_path}" );
			self::empty_directory( $plugin_abs );
		} else {
			wp_mkdir_p( $plugin_abs );
		}

		// Index zip entries for chunked extraction.
		$zip = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			@unlink( $zip_path );
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
			'backup_path' => $backup_path,
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
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}

		$plugin_abs = self::plugin_dir( $folder );
		$zip        = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			$state['status']   = 'error';
			$state['errors'][] = 'باز کردن zip ناموفق';
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
			$dest  = $plugin_abs . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );

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

			if ( false === @file_put_contents( $dest, $content ) ) {
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
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
			$state['entries']     = array();
			@unlink( $zip_path );
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
