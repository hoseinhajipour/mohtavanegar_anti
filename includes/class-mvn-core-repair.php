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

	/**
	 * Paths / prefixes that must NEVER be overwritten from the zip.
	 */
	private static function protected_rel( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', $rel ), '/' );
		// Strip leading "wordpress_core/" from zip entry names.
		if ( 0 === strpos( $rel, 'wordpress_core/' ) ) {
			$rel = substr( $rel, strlen( 'wordpress_core/' ) );
		}
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
		$name = str_replace( '\\', '/', $entry_name );
		if ( 0 === strpos( $name, 'wordpress_core/' ) ) {
			$name = substr( $name, strlen( 'wordpress_core/' ) );
		}
		$name = ltrim( $name, '/' );
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
		$out = array(
			'exists'   => is_file( MVN_SOURCE_ZIP ),
			'size'     => is_file( MVN_SOURCE_ZIP ) ? filesize( MVN_SOURCE_ZIP ) : 0,
			'readable' => is_file( MVN_SOURCE_ZIP ) && is_readable( MVN_SOURCE_ZIP ),
			'zip_ok'   => false,
			'files'    => 0,
		);
		if ( $out['readable'] && class_exists( 'ZipArchive' ) ) {
			$zip = new ZipArchive();
			if ( true === $zip->open( MVN_SOURCE_ZIP ) ) {
				$out['zip_ok'] = true;
				$out['files']  = $zip->numFiles;
				$zip->close();
			}
		}
		return $out;
	}
}
