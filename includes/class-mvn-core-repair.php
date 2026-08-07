<?php
/**
 * Core repair — extract bundled wordpress_core.zip and overwrite infected core files.
 * Never overwrites wp-config.php or wp-content.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Core_Repair {

	const STATE_KEY = 'core_repair';
	const CHUNK     = 25;
	const META_KEY  = 'mvn_core_zip_meta';
	const DOWNLOAD_URL = 'https://wordpress.org/latest.zip';

	/**
	 * Strip leading wordpress/ or wordpress_core/ from zip entry names.
	 */
	public static function strip_zip_root( $name ) {
		$name = ltrim( str_replace( '\\', '/', $name ), '/' );
		$prefixes = array( 'wordpress_core/', 'wordpress/' );
		foreach ( $prefixes as $p ) {
			if ( 0 === strpos( $name, $p ) ) {
				return substr( $name, strlen( $p ) );
			}
		}
		return $name;
	}

	/**
	 * Paths / prefixes that must NEVER be overwritten from the zip.
	 */
	private static function protected_rel( $rel ) {
		$rel = self::strip_zip_root( $rel );
		if ( '' === $rel || '/' === substr( $rel, -1 ) ) {
			return true; // directory entry
		}
		$deny = array(
			'wp-config.php',
			'wp-content/',
			'.htaccess',
			'wp-config-sample.php', // keep, but not critical — still skip to be safe if customized
		);
		foreach ( $deny as $d ) {
			if ( $rel === rtrim( $d, '/' ) || 0 === strpos( $rel, $d ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Normalize a zip entry path to a site-relative path, or false if protected/invalid.
	 */
	private static function entry_to_rel( $entry_name ) {
		$name = self::strip_zip_root( $entry_name );
		if ( '' === $name || '/' === substr( $name, -1 ) ) {
			return false;
		}
		if ( self::protected_rel( $name ) ) {
			return false;
		}
		// Only restore known core trees + root PHP files.
		$allowed_prefixes = array( 'wp-admin/', 'wp-includes/' );
		$allowed_roots    = array(
			'index.php', 'license.txt', 'readme.html', 'wp-activate.php', 'wp-blog-header.php',
			'wp-comments-post.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php',
			'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php',
			'xmlrpc.php',
		);
		$ok = in_array( $name, $allowed_roots, true );
		if ( ! $ok ) {
			foreach ( $allowed_prefixes as $p ) {
				if ( 0 === strpos( $name, $p ) ) {
					$ok = true;
					break;
				}
			}
		}
		return $ok ? $name : false;
	}

	/**
	 * Start a repair job: open zip, build file list.
	 */
	public static function start() {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error( 'no_zip', 'افزونه ZipArchive در PHP فعال نیست.' );
		}
		if ( ! is_file( MVN_SOURCE_ZIP ) ) {
			return new WP_Error( 'no_zip_file', 'فایل wordpress_core.zip در پوشه sources پلاگین پیدا نشد.' );
		}

		$zip = new ZipArchive();
		$res = $zip->open( MVN_SOURCE_ZIP );
		if ( true !== $res ) {
			return new WP_Error( 'zip_open', 'باز کردن آرشیو هسته ناموفق بود (کد: ' . $res . ').' );
		}

		$entries = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$rel = self::entry_to_rel( $stat['name'] );
			if ( ! $rel ) {
				continue;
			}
			$entries[] = array(
				'index' => $i,
				'rel'   => $rel,
				'size'  => isset( $stat['size'] ) ? (int) $stat['size'] : 0,
			);
		}
		$zip->close();

		$state = array(
			'id'         => gmdate( 'YmdHis' ),
			'status'     => 'running',
			'mode'       => 'full',
			'started_at' => gmdate( 'c' ),
			'total'      => count( $entries ),
			'cursor'     => 0,
			'written'    => 0,
			'skipped'    => 0,
			'errors'     => array(),
			'entries'    => $entries,
		);
		mvn_state_write( self::STATE_KEY, $state );
		mvn_log( 'Core repair started: files=' . $state['total'] );
		return $state;
	}

	/**
	 * Start selective repair for specific relative core paths (modified/missing).
	 *
	 * @param string[] $rels Site-relative paths.
	 * @return array|WP_Error
	 */
	public static function start_selective( $rels ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error( 'no_zip', 'افزونه ZipArchive در PHP فعال نیست.' );
		}
		if ( ! is_file( MVN_SOURCE_ZIP ) ) {
			return new WP_Error( 'no_zip_file', 'فایل wordpress_core.zip در پوشه sources پلاگین پیدا نشد.' );
		}

		$want = array();
		foreach ( (array) $rels as $rel ) {
			$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
			if ( $rel && false === strpos( $rel, '..' ) && mvn_is_core_path( $rel ) ) {
				$want[ $rel ] = true;
			}
		}
		if ( empty( $want ) ) {
			return new WP_Error( 'empty', 'هیچ فایل هسته‌ای معتبری برای تعمیر انتخابی یافت نشد.' );
		}

		$zip = new ZipArchive();
		$res = $zip->open( MVN_SOURCE_ZIP );
		if ( true !== $res ) {
			return new WP_Error( 'zip_open', 'باز کردن آرشیو هسته ناموفق بود (کد: ' . $res . ').' );
		}

		$entries = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$rel = self::entry_to_rel( $stat['name'] );
			if ( ! $rel || empty( $want[ $rel ] ) ) {
				continue;
			}
			$entries[] = array(
				'index' => $i,
				'rel'   => $rel,
				'size'  => isset( $stat['size'] ) ? (int) $stat['size'] : 0,
			);
			unset( $want[ $rel ] );
		}
		$zip->close();

		if ( empty( $entries ) ) {
			return new WP_Error( 'not_in_zip', 'هیچ‌کدام از فایل‌های انتخابی داخل wordpress_core.zip نبودند. ابتدا «دریافت آخرین نسخه» را بزنید.' );
		}

		$state = array(
			'id'         => gmdate( 'YmdHis' ) . '-sel',
			'status'     => 'running',
			'mode'       => 'selective',
			'started_at' => gmdate( 'c' ),
			'total'      => count( $entries ),
			'cursor'     => 0,
			'written'    => 0,
			'skipped'    => 0,
			'errors'     => array(),
			'entries'    => $entries,
			'missing_in_zip' => array_keys( $want ),
		);
		mvn_state_write( self::STATE_KEY, $state );
		mvn_log( 'Core selective repair started: files=' . $state['total'] );
		return $state;
	}

	/**
	 * Collect damaged core paths from last scan issues and start selective repair.
	 */
	public static function start_from_issues() {
		$issues = class_exists( 'MVN_Scanner' ) ? MVN_Scanner::get_issues() : array();
		$rels   = array();
		foreach ( $issues as $iss ) {
			if ( empty( $iss['source'] ) || 'core' !== $iss['source'] ) {
				continue;
			}
			$sig = isset( $iss['sig'] ) ? $iss['sig'] : '';
			if ( ! in_array( $sig, array( 'core_checksum_modified', 'core_checksum_missing' ), true ) ) {
				continue;
			}
			if ( ! empty( $iss['rel'] ) ) {
				$rels[] = $iss['rel'];
			}
		}
		$rels = array_values( array_unique( $rels ) );
		return self::start_selective( $rels );
	}

	/**
	 * Repair a single core file from the bundled zip (synchronous).
	 *
	 * @param string $rel Site-relative core path.
	 * @return true|WP_Error
	 */
	public static function repair_one( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		if ( ! $rel || ! mvn_is_core_path( $rel ) ) {
			return new WP_Error( 'bad_path', 'مسیر هسته نامعتبر است.' );
		}
		if ( ! class_exists( 'ZipArchive' ) || ! is_file( MVN_SOURCE_ZIP ) ) {
			return new WP_Error( 'no_zip', 'آرشیو هسته در دسترس نیست.' );
		}

		$zip = new ZipArchive();
		if ( true !== $zip->open( MVN_SOURCE_ZIP ) ) {
			return new WP_Error( 'zip_open', 'باز کردن آرشیو هسته ناموفق بود.' );
		}

		$found = false;
		$content = false;
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$entry_rel = self::entry_to_rel( $stat['name'] );
			if ( $entry_rel === $rel ) {
				$content = $zip->getFromIndex( $i );
				$found   = true;
				break;
			}
		}
		$zip->close();

		if ( ! $found || false === $content ) {
			return new WP_Error( 'not_in_zip', 'این فایل در wordpress_core.zip نیست. نسخه zip را به‌روز کنید.' );
		}

		$abs = mvn_abs_path( $rel );
		if ( ! $abs ) {
			return new WP_Error( 'bad_path', 'مسیر نامعتبر.' );
		}
		$parent = dirname( $abs );
		if ( ! is_dir( $parent ) ) {
			wp_mkdir_p( $parent );
		}
		if ( is_file( $abs ) ) {
			MVN_Quarantine::store( $rel, array( 'reason' => 'pre-core-repair' ) );
		}
		if ( false === @file_put_contents( $abs, $content ) ) {
			return new WP_Error( 'write_fail', 'نوشتن فایل هسته ناموفق بود.' );
		}
		@chmod( $abs, 0644 );
		mvn_log( "Core file repaired: {$rel}" );
		return true;
	}

	/**
	 * Process next CHUNK of core files.
	 */
	public static function tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) || 'running' !== $state['status'] ) {
			return $state;
		}
		if ( ! class_exists( 'ZipArchive' ) ) {
			$state['status'] = 'error';
			$state['errors'][] = 'ZipArchive missing';
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}

		$zip = new ZipArchive();
		if ( true !== $zip->open( MVN_SOURCE_ZIP ) ) {
			$state['status']   = 'error';
			$state['errors'][] = 'Cannot reopen zip';
			mvn_state_write( self::STATE_KEY, $state );
			return $state;
		}

		$start = (int) $state['cursor'];
		$total = (int) $state['total'];
		$end   = min( $start + self::CHUNK, $total );
		$entries = isset( $state['entries'] ) ? $state['entries'] : array();

		for ( $i = $start; $i < $end; $i++ ) {
			$entry = $entries[ $i ];
			$rel   = $entry['rel'];
			$abs   = mvn_abs_path( $rel );
			if ( ! $abs ) {
				$state['skipped']++;
				continue;
			}

			$content = $zip->getFromIndex( $entry['index'] );
			if ( false === $content ) {
				$state['errors'][] = $rel . ': خواندن از zip ناموفق';
				continue;
			}

			// Skip write if identical (saves IO and preserves mtime).
			if ( is_file( $abs ) && (string) @file_get_contents( $abs ) === $content ) {
				$state['skipped']++;
				continue;
			}

			$parent = dirname( $abs );
			if ( ! is_dir( $parent ) ) {
				wp_mkdir_p( $parent );
			}

			$ok = @file_put_contents( $abs, $content );
			if ( false === $ok ) {
				$state['errors'][] = $rel . ': نوشتن ناموفق';
				continue;
			}
			@chmod( $abs, 0644 );
			$state['written']++;
		}

		$zip->close();
		$state['cursor']     = $end;
		$state['updated_at'] = gmdate( 'c' );

		if ( $end >= $total ) {
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
			$state['entries']     = array(); // free memory
			mvn_log( 'Core repair done: written=' . $state['written'] . ' skipped=' . $state['skipped'] . ' errors=' . count( $state['errors'] ) );
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function get_state() {
		return mvn_state_read( self::STATE_KEY );
	}

	/**
	 * Quick check: does the source zip look present and valid?
	 */
	public static function source_status() {
		$meta = get_option( self::META_KEY, array() );
		$out  = array(
			'exists'         => is_file( MVN_SOURCE_ZIP ),
			'size'           => is_file( MVN_SOURCE_ZIP ) ? filesize( MVN_SOURCE_ZIP ) : 0,
			'readable'       => is_file( MVN_SOURCE_ZIP ) && is_readable( MVN_SOURCE_ZIP ),
			'zip_ok'         => false,
			'files'          => 0,
			'version'        => isset( $meta['version'] ) ? (string) $meta['version'] : '',
			'downloaded_at'  => isset( $meta['downloaded_at'] ) ? (string) $meta['downloaded_at'] : '',
			'writable'       => is_dir( dirname( MVN_SOURCE_ZIP ) ) && is_writable( dirname( MVN_SOURCE_ZIP ) ),
		);
		if ( $out['readable'] && class_exists( 'ZipArchive' ) ) {
			$zip = new ZipArchive();
			if ( true === $zip->open( MVN_SOURCE_ZIP ) ) {
				$out['zip_ok'] = true;
				$out['files']  = $zip->numFiles;
				if ( '' === $out['version'] ) {
					$out['version'] = self::version_from_zip( $zip );
				}
				$zip->close();
			}
		}
		return $out;
	}

	/**
	 * Read $wp_version from wp-includes/version.php inside an open ZipArchive.
	 *
	 * @param ZipArchive $zip Open archive.
	 * @return string
	 */
	private static function version_from_zip( $zip ) {
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$name = $zip->getNameIndex( $i );
			if ( ! $name ) {
				continue;
			}
			$rel = self::strip_zip_root( $name );
			if ( 'wp-includes/version.php' !== $rel ) {
				continue;
			}
			$content = $zip->getFromIndex( $i );
			if ( false === $content ) {
				return '';
			}
			if ( preg_match( '/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m ) ) {
				return $m[1];
			}
			return '';
		}
		return '';
	}

	/**
	 * Download latest WordPress zip from wordpress.org into sources/wordpress_core.zip.
	 *
	 * @return array|WP_Error Updated source_status() on success.
	 */
	public static function download_latest() {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error( 'no_zip', 'افزونه ZipArchive در PHP فعال نیست.' );
		}

		$dest_dir = dirname( MVN_SOURCE_ZIP );
		if ( ! is_dir( $dest_dir ) ) {
			wp_mkdir_p( $dest_dir );
		}
		if ( ! is_writable( $dest_dir ) ) {
			return new WP_Error( 'not_writable', 'پوشه sources پلاگین قابل نوشتن نیست.' );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		@set_time_limit( 600 );

		$url = apply_filters( 'mvn_wordpress_core_download_url', self::DOWNLOAD_URL );
		mvn_log( 'Core zip: downloading latest WordPress from ' . $url );

		$tmp = download_url( $url, 600 );
		if ( is_wp_error( $tmp ) ) {
			return new WP_Error( 'download_fail', 'دانلود از wordpress.org ناموفق: ' . $tmp->get_error_message() );
		}

		$zip = new ZipArchive();
		$res = $zip->open( $tmp );
		if ( true !== $res ) {
			@unlink( $tmp );
			return new WP_Error( 'bad_zip', 'آرشیو دانلودشده قابل باز شدن نیست (کد: ' . $res . ').' );
		}

		$version  = self::version_from_zip( $zip );
		$num_files = $zip->numFiles;
		$has_core = ( '' !== $version );
		if ( ! $has_core ) {
			for ( $i = 0; $i < min( $num_files, 200 ); $i++ ) {
				$name = $zip->getNameIndex( $i );
				if ( ! $name ) {
					continue;
				}
				$rel = self::strip_zip_root( $name );
				if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
					$has_core = true;
					break;
				}
			}
		}
		$zip->close();

		if ( ! $has_core ) {
			@unlink( $tmp );
			return new WP_Error( 'invalid_core', 'آرشیو دانلودشده هسته وردپرس معتبر نیست.' );
		}

		$bak = MVN_SOURCE_ZIP . '.bak';
		if ( is_file( MVN_SOURCE_ZIP ) ) {
			@unlink( $bak );
			@rename( MVN_SOURCE_ZIP, $bak );
		}

		$moved = @rename( $tmp, MVN_SOURCE_ZIP );
		if ( ! $moved ) {
			$moved = @copy( $tmp, MVN_SOURCE_ZIP );
			@unlink( $tmp );
		}
		if ( ! $moved || ! is_file( MVN_SOURCE_ZIP ) ) {
			if ( is_file( $bak ) ) {
				@rename( $bak, MVN_SOURCE_ZIP );
			}
			return new WP_Error( 'save_fail', 'ذخیره فایل wordpress_core.zip ناموفق بود.' );
		}

		if ( is_file( $bak ) ) {
			@unlink( $bak );
		}

		update_option(
			self::META_KEY,
			array(
				'version'       => $version,
				'downloaded_at' => gmdate( 'c' ),
				'size'          => filesize( MVN_SOURCE_ZIP ),
				'files'         => $num_files,
				'source_url'    => $url,
			),
			false
		);

		mvn_log( 'Core zip updated: version=' . ( $version ? $version : '?' ) . ' files=' . $num_files );
		return self::source_status();
	}
}
