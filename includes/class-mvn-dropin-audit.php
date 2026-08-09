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

			// Hex zip droppers in wp-content root (e.g. a78b06dc.zip).
			if ( preg_match( '/^\.?[a-f0-9]{6,16}\.zip$/i', $entry ) ) {
				self::flag(
					$state,
					'wp-content/' . $entry,
					'wpcontent_hex_zip',
					'آرشیو hex مشکوک در ریشه wp-content',
					'نام تصادفی hex + zip در ریشه محتوا — معمولاً بک‌آپ/دراپر بدافزار برای reinfection.',
					'quarantine_delete',
					@file_get_contents( $abs )
				);
				continue;
			}

			// .user.ini often holds auto_prepend_file backdoors.
			if ( '.user.ini' === $entry || 'user.ini' === $entry || 'php.ini' === $entry ) {
				$content = (string) @file_get_contents( $abs );
				$bad     = (bool) preg_match( '/auto_prepend_file|auto_append_file/i', $content )
					|| preg_match( '/[a-f0-9]{6,}\.php/i', $content );
				self::flag(
					$state,
					'wp-content/' . $entry,
					$bad ? 'user_ini_prepend' : 'user_ini_wpcontent',
					$bad ? '.user.ini با auto_prepend (بک‌دور)' : '.user.ini در ریشه wp-content',
					$bad
						? 'این فایل PHP را قبل از وردپرس لود می‌کند و باعث قفل/بازنویسی بدافزار می‌شود. اول این را حذف کنید.'
						: 'وجود .user.ini در wp-content غیرمعمول است — بررسی و حذف توصیه می‌شود.',
					'quarantine_delete',
					$content
				);
				continue;
			}

			$ext = strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'php8' ), true ) ) {
				continue;
			}

			$content = @file_get_contents( $abs );
			$content = is_string( $content ) ? $content : '';

			// Hex-named / hidden PHP shells: 81a4376c.php or .81a4376c.php
			if ( preg_match( '/^\.?[a-f0-9]{6,16}\.php$/i', $entry ) ) {
				self::flag(
					$state,
					'wp-content/' . $entry,
					'wpcontent_hex_php',
					'فایل PHP با نام hex در ریشه wp-content',
					'الگوی کلاسیک webshell / dropper. این فایل اغلب مانع حذف بقیه می‌شود.',
					'quarantine_delete',
					$content
				);
				continue;
			}

			// Legitimate drop-in names: still flag if clearly malicious.
			if ( in_array( $entry, $known, true ) ) {
				if ( 'db.php' === $entry && self::db_php_looks_malicious( $content ) ) {
					self::flag(
						$state,
						'wp-content/db.php',
						'suspicious_db_dropin',
						'dropin مشکوک db.php',
						'db.php رسمی می‌تواند HyperDB/کش باشد؛ این نمونه نشانه obfuscation/بک‌دور دارد یا با shellهای hex هم‌زمان است.',
						'quarantine_delete',
						$content
					);
				}
				continue;
			}

			self::flag(
				$state,
				'wp-content/' . $entry,
				'unexpected_dropin',
				'فایل PHP غیرمنتظره در ریشه wp-content (drop-in مشکوک)',
				'فقط drop-inهای رسمی وردپرس در ریشه wp-content مجازند. این فایل می‌تواند بک‌دور باشد.',
				'quarantine_delete',
				$content
			);
		}
	}

	/**
	 * Heuristic: db.php drop-in used as malware loader.
	 *
	 * @param string $content File contents.
	 */
	private static function db_php_looks_malicious( $content ) {
		if ( '' === $content ) {
			return false;
		}
		// Our temporary safe bootstrap — never flag.
		if ( false !== strpos( $content, 'MVN Safe DB Bootstrap' ) ) {
			return false;
		}
		// Companion hex shells in same folder strongly imply compromised db.php.
		$dir = WP_CONTENT_DIR;
		foreach ( scandir( $dir ) ?: array() as $entry ) {
			if ( preg_match( '/^\.?[a-f0-9]{6,16}\.php$/i', $entry ) ) {
				return true;
			}
		}
		if ( preg_match( '/\b(?:eval|assert|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content )
			&& preg_match( '/base64_decode|\\$_(?:POST|GET|REQUEST|COOKIE)|create_function|preg_replace\s*\(\s*[\'"].*\/e/i', $content ) ) {
			return true;
		}
		if ( preg_match( '/auto_prepend_file|81a4376c|\.[a-f0-9]{8}\.php/i', $content ) ) {
			return true;
		}
		// Heavy obfuscation without WordPress DB API markers.
		if ( substr_count( $content, '\\x' ) > 80 && ! preg_match( '/wpdb|DB_HOST|mysqli_connect|hyperdb/i', $content ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @param array       $state   Scan state.
	 * @param string      $rel     Relative path.
	 * @param string      $sig     Signature id.
	 * @param string      $label   Label.
	 * @param string      $detail  Detail.
	 * @param string      $action  Fix action.
	 * @param string|false $content Content.
	 */
	private static function flag( &$state, $rel, $sig, $label, $detail, $action, $content = '' ) {
		$content = is_string( $content ) ? $content : '';
		$hash    = '' !== $content ? md5( $content ) : md5( $rel . $sig );
		$snippet = '' !== $content ? substr( preg_replace( '/\s+/', ' ', $content ), 0, 160 ) : '';
		if ( ! MVN_Scanner::add_finding(
			$state,
			array(
				'rel'      => $rel,
				'sig'      => $sig,
				'label'    => $label,
				'severity' => 'critical',
				'detail'   => $detail,
				'action'   => $action,
				'snippet'  => $snippet,
				'source'   => 'dropin',
			),
			$content,
			$hash
		) ) {
			return;
		}
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
