<?php
/**
 * Theme repair — download fresh copies from WordPress.org and replace local theme files.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Theme_Repair {

	const STATE_KEY = 'theme_repair';
	const CHUNK     = 30;

	/**
	 * Catalog of installed themes for the repair UI.
	 */
	public static function catalog_status() {
		$themes = wp_get_themes();
		$current = get_stylesheet();
		$parent  = get_template();
		$out     = array();

		foreach ( $themes as $stylesheet => $theme ) {
			$abs = $theme->get_stylesheet_directory();
			$file_count = 0;
			if ( is_dir( $abs ) ) {
				$file_count = count( mvn_list_files( $abs, 200000 ) );
			}
			$out[] = array(
				'slug'       => $stylesheet,
				'name'       => $theme->get( 'Name' ),
				'version'    => $theme->get( 'Version' ),
				'installed'  => true,
				'active'     => ( $stylesheet === $current ),
				'parent'     => ( $stylesheet === $parent && $stylesheet !== $current ),
				'file_count' => $file_count,
				'download'   => self::download_url_for( $stylesheet ),
			);
		}

		usort(
			$out,
			function ( $a, $b ) {
				if ( ! empty( $a['active'] ) !== ! empty( $b['active'] ) ) {
					return ! empty( $a['active'] ) ? -1 : 1;
				}
				return strcasecmp( $a['name'], $b['name'] );
			}
		);

		return $out;
	}

	private static function download_url_for( $slug ) {
		return 'https://downloads.wordpress.org/theme/' . rawurlencode( $slug ) . '.latest-stable.zip';
	}

	private static function theme_dir( $slug ) {
		return trailingslashit( get_theme_root() ) . $slug;
	}

	private static function backups_dir() {
		mvn_ensure_data_dirs();
		$dir = mvn_data_dir() . '/backups/themes';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		return $dir;
	}

	private static function temp_zip_path( $slug ) {
		return mvn_data_dir() . '/state/theme-' . sanitize_key( $slug ) . '.zip';
	}

	/**
	 * Start theme repair from wordpress.org.
	 *
	 * @param string $slug Theme stylesheet slug.
	 * @return array|WP_Error
	 */
	public static function start( $slug ) {
		$slug = sanitize_title( $slug );
		if ( ! $slug ) {
			return new WP_Error( 'bad_slug', 'شناسه قالب نامعتبر است.' );
		}
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error( 'no_zip', 'افزونه ZipArchive در PHP فعال نیست.' );
		}

		$theme = wp_get_theme( $slug );
		$name  = $theme->exists() ? $theme->get( 'Name' ) : $slug;

		require_once ABSPATH . 'wp-admin/includes/file.php';
		@set_time_limit( 300 );

		$theme_abs = self::theme_dir( $slug );
		$zip_path  = self::temp_zip_path( $slug );

		mvn_log( "Theme repair: downloading {$slug} from wordpress.org" );
		$tmp = download_url( self::download_url_for( $slug ), 300 );
		if ( is_wp_error( $tmp ) ) {
			return new WP_Error(
				'download_fail',
				'دانلود قالب از مخزن ناموفق بود (احتمالاً قالب پریمیوم/خارج از.org است): ' . $tmp->get_error_message()
			);
		}

		if ( ! @rename( $tmp, $zip_path ) ) {
			if ( ! @copy( $tmp, $zip_path ) ) {
				@unlink( $tmp );
				return new WP_Error( 'save_fail', 'ذخیره آرشیو قالب ناموفق بود.' );
			}
			@unlink( $tmp );
		}

		$zip_root = self::detect_zip_root( $zip_path, $slug );
		if ( ! $zip_root ) {
			@unlink( $zip_path );
			return new WP_Error( 'bad_zip', 'ساختار آرشیو قالب نامعتبر است.' );
		}

		$backup_path = '';
		if ( is_dir( $theme_abs ) ) {
			$backup = self::backup_theme( $theme_abs, $slug );
			if ( ! $backup ) {
				@unlink( $zip_path );
				return new WP_Error( 'backup_fail', 'پشتیبان‌گیری از قالب فعلی ناموفق بود.' );
			}
			$backup_path = $backup['path'];
			mvn_log( "Theme repair: backed up {$slug} ({$backup['type']}) -> {$backup_path}" );
			self::empty_directory( $theme_abs );
		} else {
			wp_mkdir_p( $theme_abs );
		}

		$zip = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			@unlink( $zip_path );
			return new WP_Error( 'zip_open', 'باز کردن آرشیو قالب ناموفق بود.' );
		}

		$prefix  = rtrim( $zip_root, '/' ) . '/';
		$entries = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$name_entry = str_replace( '\\', '/', $stat['name'] );
			if ( '/' === substr( $name_entry, -1 ) ) {
				continue;
			}
			if ( 0 !== strpos( $name_entry, $prefix ) ) {
				continue;
			}
			$rel = substr( $name_entry, strlen( $prefix ) );
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
			return new WP_Error( 'empty_zip', 'آرشیو قالب فایل معتبری نداشت.' );
		}

		$state = array(
			'status'      => 'running',
			'slug'        => $slug,
			'name'        => $name,
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
		mvn_log( "Theme repair started: {$slug} files=" . $state['total'] );
		return $state;
	}

	public static function tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) || 'running' !== $state['status'] ) {
			return $state;
		}

		$zip_path = isset( $state['zip_path'] ) ? $state['zip_path'] : '';
		$slug     = isset( $state['slug'] ) ? $state['slug'] : '';
		if ( ! $zip_path || ! is_file( $zip_path ) || ! $slug ) {
			$state['status']   = 'error';
			$state['errors'][] = 'zip یا slug نامعتبر';
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}

		$theme_abs = self::theme_dir( $slug );
		$zip       = new ZipArchive();
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
			$dest  = $theme_abs . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );

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
			mvn_log( 'Theme repair done: ' . $state['slug'] . ' written=' . $state['written'] );
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function get_state() {
		return mvn_state_read( self::STATE_KEY );
	}

	private static function detect_zip_root( $zip_path, $slug ) {
		$zip = new ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			return false;
		}
		$found = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$parts = explode( '/', str_replace( '\\', '/', $stat['name'] ) );
			if ( ! empty( $parts[0] ) ) {
				$found[ $parts[0] ] = true;
			}
		}
		$zip->close();
		if ( isset( $found[ $slug ] ) ) {
			return $slug;
		}
		$roots = array_keys( $found );
		return ! empty( $roots ) ? $roots[0] : false;
	}

	private static function backup_theme( $source_dir, $slug ) {
		$backups = self::backups_dir();
		if ( ! is_writable( $backups ) ) {
			return false;
		}
		$stamp    = gmdate( 'Ymd-His' );
		$zip_path = $backups . '/' . $slug . '-' . $stamp . '.zip';
		if ( self::zip_directory( $source_dir, $slug, $zip_path ) ) {
			return array( 'type' => 'zip', 'path' => $zip_path );
		}
		@unlink( $zip_path );
		$dir_path = $backups . '/' . $slug . '-' . $stamp;
		if ( self::copy_directory( $source_dir, $dir_path ) ) {
			return array( 'type' => 'dir', 'path' => $dir_path );
		}
		return false;
	}

	private static function zip_directory( $source_dir, $folder, $dest_zip ) {
		if ( ! class_exists( 'ZipArchive' ) || ! is_dir( $source_dir ) ) {
			return false;
		}
		$zip = new ZipArchive();
		if ( true !== $zip->open( $dest_zip, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
			return false;
		}
		$source_dir = rtrim( str_replace( '\\', '/', $source_dir ), '/' );
		foreach ( mvn_list_files_in( $source_dir, 500000 ) as $rel ) {
			$abs = $source_dir . '/' . str_replace( '\\', '/', $rel );
			if ( is_file( $abs ) && is_readable( $abs ) ) {
				$zip->addFile( $abs, $folder . '/' . str_replace( '\\', '/', $rel ) );
			}
		}
		$zip->close();
		return is_file( $dest_zip ) && filesize( $dest_zip ) > 0;
	}

	private static function copy_directory( $src, $dst ) {
		if ( ! is_dir( $src ) ) {
			return false;
		}
		wp_mkdir_p( $dst );
		$src = rtrim( str_replace( '\\', '/', $src ), '/' );
		foreach ( mvn_list_files_in( $src, 500000 ) as $rel ) {
			$from = $src . '/' . str_replace( '\\', '/', $rel );
			$to   = rtrim( $dst, '/\\' ) . '/' . str_replace( '\\', '/', $rel );
			if ( ! is_file( $from ) ) {
				continue;
			}
			$parent = dirname( $to );
			if ( ! is_dir( $parent ) ) {
				wp_mkdir_p( $parent );
			}
			if ( ! @copy( $from, $to ) ) {
				return false;
			}
		}
		return true;
	}

	private static function empty_directory( $dir ) {
		$dir = rtrim( str_replace( '\\', '/', $dir ), '/' );
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( mvn_list_files_in( $dir, 500000 ) as $rel ) {
			$abs = $dir . '/' . str_replace( '\\', '/', $rel );
			if ( is_file( $abs ) ) {
				@unlink( $abs );
			}
		}
		// Remove empty subdirs (best-effort, bottom-up via repeated pass).
		$paths = array();
		$it    = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $it as $file ) {
			if ( $file->isDir() ) {
				@rmdir( $file->getPathname() );
			}
		}
	}
}
