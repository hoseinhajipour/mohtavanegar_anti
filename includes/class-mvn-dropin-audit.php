<?php
/**
 * Drop-in / MU-plugin / .user.ini audit — unexpected loadable files.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Dropin_Audit {

	/**
	 * Known legitimate WP drop-ins in wp-content root.
	 */
	public static function known_dropins() {
		$list = array(
			'object-cache.php',
			'advanced-cache.php',
			'db.php',
			'sunrise.php',
			'maintenance.php',
			'install.php',
			'blog-deleted.php',
			'blog-inactive.php',
			'blog-suspended.php',
			'db-error.php',
			'fatal-error-handler.php',
			'php-error.php',
			'index.php',
		);
		return apply_filters( 'mvn_known_dropins', $list );
	}

	/**
	 * Collect special paths that must always be in the file catalog.
	 *
	 * @return string[] Relative paths.
	 */
	public static function extra_scan_paths() {
		$paths = array();

		foreach ( self::known_dropins() as $name ) {
			$rel = 'wp-content/' . $name;
			$abs = mvn_abs_path( $rel );
			if ( $abs && is_file( $abs ) ) {
				$paths[] = $rel;
			}
		}

		// Any other PHP directly in wp-content root.
		$content = WP_CONTENT_DIR;
		if ( is_dir( $content ) ) {
			foreach ( scandir( $content ) ?: array() as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$abs = $content . '/' . $entry;
				if ( ! is_file( $abs ) ) {
					continue;
				}
				$ext = strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) );
				if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'php8' ), true ) ) {
					$paths[] = 'wp-content/' . $entry;
				}
				if ( in_array( strtolower( $entry ), array( '.user.ini', 'php.ini', '.htaccess' ), true ) ) {
					$paths[] = 'wp-content/' . $entry;
				}
			}
		}

		// Root .user.ini / php.ini
		foreach ( array( '.user.ini', 'php.ini' ) as $ini ) {
			if ( is_file( ABSPATH . $ini ) ) {
				$paths[] = $ini;
			}
		}

		// MU-plugins tree.
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$mu_files = mvn_list_files( WPMU_PLUGIN_DIR, 50000 );
			$paths    = array_merge( $paths, $mu_files );
		} elseif ( is_dir( WP_CONTENT_DIR . '/mu-plugins' ) ) {
			$paths = array_merge( $paths, mvn_list_files( WP_CONTENT_DIR . '/mu-plugins', 50000 ) );
		}

		// Find .user.ini under ABSPATH (limited walk of shallow dirs).
		$paths = array_merge( $paths, self::find_user_ini() );

		return array_values( array_unique( $paths ) );
	}

	/**
	 * Shallow search for .user.ini (ABSPATH, wp-admin, wp-content, uploads).
	 */
	private static function find_user_ini() {
		$roots = array(
			ABSPATH,
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
			WP_CONTENT_DIR,
			WP_CONTENT_DIR . '/uploads',
			WP_CONTENT_DIR . '/plugins',
			WP_CONTENT_DIR . '/themes',
			WP_CONTENT_DIR . '/mu-plugins',
		);
		$found = array();
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			$file = rtrim( $root, '/\\' ) . '/.user.ini';
			if ( is_file( $file ) ) {
				$found[] = mvn_rel_path( $file );
			}
			// One level deeper for uploads year folders only when uploads root.
			if ( rtrim( str_replace( '\\', '/', $root ), '/' ) === rtrim( str_replace( '\\', '/', WP_CONTENT_DIR . '/uploads' ), '/' ) ) {
				foreach ( scandir( $root ) ?: array() as $entry ) {
					if ( '.' === $entry || '..' === $entry || ! is_dir( $root . '/' . $entry ) ) {
						continue;
					}
					$nested = $root . '/' . $entry . '/.user.ini';
					if ( is_file( $nested ) ) {
						$found[] = mvn_rel_path( $nested );
					}
				}
			}
		}
		return $found;
	}

	/**
	 * Run structural audit and append findings (unexpected drop-ins).
	 *
	 * @param array $state Scan state by reference.
	 */
	public static function audit( &$state ) {
		$known = self::known_dropins();
		$dir   = WP_CONTENT_DIR;
		if ( ! is_dir( $dir ) ) {
			return;
		}

		foreach ( scandir( $dir ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$abs = $dir . '/' . $entry;
			if ( ! is_file( $abs ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'php8' ), true ) ) {
				continue;
			}
			if ( in_array( $entry, $known, true ) ) {
				continue;
			}

			$rel     = 'wp-content/' . $entry;
			$content = @file_get_contents( $abs );
			$hash    = is_string( $content ) ? md5( $content ) : '';
			$snippet = is_string( $content ) ? substr( preg_replace( '/\s+/', ' ', $content ), 0, 160 ) : '';

			if ( MVN_Scanner::add_finding(
				$state,
				array(
					'rel'      => $rel,
					'sig'      => 'unexpected_dropin',
					'label'    => 'فایل PHP غیرمنتظره در ریشه wp-content (drop-in مشکوک)',
					'severity' => 'critical',
					'detail'   => 'فقط drop-inهای رسمی وردپرس در ریشه wp-content مجازند. این فایل می‌تواند بک‌دور باشد.',
					'action'   => 'quarantine_delete',
					'snippet'  => $snippet,
					'source'   => 'dropin',
				),
				is_string( $content ) ? $content : '',
				$hash
			) ) {
				if ( ! isset( $state['stats']['critical'] ) ) {
					$state['stats']['critical'] = 0;
				}
				$state['stats']['critical']++;
				if ( ! isset( $state['stats']['dropin'] ) ) {
					$state['stats']['dropin'] = 0;
				}
				$state['stats']['dropin']++;
			}
		}
	}
}
