<?php
/**
 * Known malware plugin IoCs + ghost/hidden plugin detection.
 *
 * Covers families like xdav-tracker + wp-security-helper that hide from wp-admin
 * via all_plugins / pre_user_query filters while remaining on disk.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Ghost_Plugins {

	/**
	 * Known malicious plugin folder slugs (filesystem).
	 *
	 * @return string[]
	 */
	public static function malware_slugs() {
		$slugs = array(
			// xdav / stealth companion
			'xdav-tracker',
			'wp-security-helper',
			'wp-compat',
			'wp-security-patch',
			'cachefusion',
			'cdnconnect',
			// Zonal Runner Tap + common slug variants
			'zonal-runner-tap',
			'zonal_runner_tap',
			'zonal-runner',
			'zonalrunnertap',
			'zonal-runner-tap-plugin',
			// Imunify Hidden Admin Toolkit / common fakes
			'wp-content-optimizer',
			'wp-performance-tools',
			'wp-flavor',
			'flavor-sync',
			'site-toolkit-services',
			'wp-session-handler',
			'performance-enhancer',
			'wp-asset-optimizer',
			'elementor-safe-dash',
			'wp-themes-tools',
			'one-user-tools',
			'advanced-linkflow',
			'wordpress-posts-cache-engine',
		);
		return apply_filters( 'mvn_malware_plugin_slugs', $slugs );
	}

	/**
	 * Known malicious single-file plugin basenames in plugins root.
	 *
	 * @return string[]
	 */
	public static function malware_basenames() {
		$names = array(
			'xdav-tracker.php',
			'wp-security-helper.php',
			'wp-compat.php',
			'zonal-runner-tap.php',
			'zonal_runner_tap.php',
			'zonal-runner.php',
		);
		return apply_filters( 'mvn_malware_plugin_basenames', $names );
	}

	/**
	 * Regexes matched against Plugin Name header / folder (case-insensitive).
	 *
	 * @return string[]
	 */
	public static function malware_name_patterns() {
		$patterns = array(
			'/zonal[\s_-]*runner[\s_-]*tap/i',
			'/xdav[\s_-]*tracker/i',
			'/wp[\s_-]*security[\s_-]*helper/i',
			'/wp[\s_-]*content[\s_-]*optimizer/i',
			'/site[\s_-]*toolkit[\s_-]*services/i',
			'/flavor[\s_-]*sync/i',
			'/elementor[\s_-]*safe[\s_-]*dash/i',
			'/wordpress[\s_-]*posts[\s_-]*cache[\s_-]*engine/i',
			'/symfony[\s_-]*framework[\s_-]*httpkernel/i',
		);
		return apply_filters( 'mvn_malware_plugin_name_patterns', $patterns );
	}

	/**
	 * Option names used by this malware family for persistence / tracking.
	 *
	 * @return string[]
	 */
	public static function malware_option_names() {
		$names = array(
			'_pre_user_id',
			'xdav_tracker',
			'xdav-tracker',
			'wp_security_helper',
			'wp-security-helper',
			'zonal_runner_tap',
			'zonal-runner-tap',
			'_wp_ui_render_cfg',
			'_wp_cache_hash',
			'_wps_sig',
			'_sys_token',
			'_bk_hash',
			'_adm_key',
			'_wp_sys_hash',
			'_stk_sig',
		);
		return apply_filters( 'mvn_malware_option_names', $names );
	}

	/**
	 * Persistence dropper paths relative to ABSPATH / WP_CONTENT.
	 *
	 * @return string[] Relative paths that should not exist.
	 */
	public static function persistence_path_globs() {
		return apply_filters(
			'mvn_malware_persistence_paths',
			array(
				'wp-content/upgrade/wp-maintenance.tmp',
			)
		);
	}

	/**
	 * Whether a relative path belongs to a known malware plugin IoC.
	 *
	 * @param string $rel Relative path under ABSPATH.
	 * @return string|false Matched slug/basename or false.
	 */
	public static function path_ioc_match( $rel ) {
		$rel  = trim( str_replace( '\\', '/', (string) $rel ), '/' );
		$base = basename( $rel );

		foreach ( self::malware_slugs() as $slug ) {
			$prefix = 'wp-content/plugins/' . $slug;
			if ( $rel === $prefix || 0 === strpos( $rel, $prefix . '/' ) ) {
				return $slug;
			}
		}

		foreach ( self::malware_basenames() as $name ) {
			if ( 0 === strcasecmp( $base, $name ) ) {
				return $name;
			}
			if ( 0 === strcasecmp( $rel, 'wp-content/plugins/' . $name ) ) {
				return $name;
			}
		}

		// Filename anywhere containing xdav-tracker or zonal-runner-tap (droppers outside plugins/).
		if ( preg_match( '/(?:^|[\/_-])xdav[-_]?tracker(?:\.php)?$/i', $base ) ) {
			return 'xdav-tracker';
		}
		if ( preg_match( '/zonal[-_]?runner[-_]?tap/i', $base ) || preg_match( '/zonal[-_]?runner/i', $base ) ) {
			return 'zonal-runner-tap';
		}

		// wp-content root hex shells / hidden PHP / hex zip.
		if ( preg_match( '#^wp-content/\.?[a-f0-9]{6,16}\.php$#i', $rel ) ) {
			return 'wpcontent-hex-php';
		}
		if ( preg_match( '#^wp-content/\.?[a-f0-9]{6,16}\.zip$#i', $rel ) ) {
			return 'wpcontent-hex-zip';
		}

		return false;
	}

	/**
	 * Whether a db.php/advanced-cache/object-cache path is our temporary safe drop-in.
	 *
	 * @param string $abs Absolute path.
	 */
	public static function is_mvn_safe_dropin( $abs ) {
		if ( ! is_file( $abs ) ) {
			return false;
		}
		$head = (string) @file_get_contents( $abs, false, null, 0, 512 );
		return false !== strpos( $head, 'MVN Safe DB Bootstrap' )
			|| false !== strpos( $head, 'MVN Safe Cache' )
			|| false !== strpos( $head, 'MVN Safe Object Cache' )
			|| false !== strpos( $head, 'MVN Safe prepend stub' )
			|| false !== strpos( $head, 'Neutralized by Mohtavanegar Antivirus' )
			|| false !== strpos( $head, 'Neutralized by MVN Safe' );
	}

	/**
	 * Discover malware persistence files in wp-content root (hex PHP, .user.ini, zip, bad db.php).
	 *
	 * @return string[] Relative paths.
	 */
	public static function discover_wpcontent_root_iocs() {
		$found = array();
		$dir   = WP_CONTENT_DIR;
		if ( ! is_dir( $dir ) ) {
			return $found;
		}
		$has_hex_php    = false;
		$has_mu_malware = false;
		$mu             = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( $dir . '/mu-plugins' );
		if ( is_dir( $mu ) ) {
			foreach ( scandir( $mu ) ?: array() as $entry ) {
				if ( preg_match( '/zonal|xdav|security-helper|wp-[a-z0-9]{6}-loader/i', $entry ) ) {
					$has_mu_malware = true;
					$found[]        = 'wp-content/mu-plugins/' . $entry;
				}
			}
		}
		foreach ( scandir( $dir ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry || ! is_file( $dir . '/' . $entry ) ) {
				continue;
			}
			if ( self::is_mvn_safe_dropin( $dir . '/' . $entry ) ) {
				continue;
			}
			if ( preg_match( '/^\.?[a-f0-9]{6,16}\.php$/i', $entry ) ) {
				$found[]     = 'wp-content/' . $entry;
				$has_hex_php = true;
			} elseif ( preg_match( '/^\.?[a-f0-9]{6,16}\.zip$/i', $entry ) ) {
				$found[] = 'wp-content/' . $entry;
			} elseif ( in_array( $entry, array( '.user.ini', 'user.ini', 'php.ini' ), true ) ) {
				$found[] = 'wp-content/' . $entry;
			}
		}
		$db = $dir . '/db.php';
		// Any db.php under wp-content is treated as persistence (no exceptions).
		if ( is_file( $db ) ) {
			$found[] = 'wp-content/db.php';
		}
		foreach ( array( 'advanced-cache.php', 'object-cache.php' ) as $drop ) {
			$abs = $dir . '/' . $drop;
			if ( ! is_file( $abs ) || self::is_mvn_safe_dropin( $abs ) ) {
				continue;
			}
			$raw = (string) @file_get_contents( $abs );
			if ( $has_hex_php || $has_mu_malware || self::db_php_is_hostile( $raw ) ) {
				$found[] = 'wp-content/' . $drop;
			}
		}
		// All ABSPATH / wp-content user.ini variants (not only prepend-marked).
		foreach ( array( ABSPATH . '.user.ini', ABSPATH . 'user.ini', ABSPATH . 'php.ini' ) as $abs ) {
			if ( is_file( $abs ) && ! self::is_mvn_safe_dropin( $abs ) ) {
				$found[] = mvn_rel_path( $abs );
			}
		}
		return array_values( array_unique( array_filter( $found ) ) );
	}

	/**
	 * Hostile markers for db.php / advanced-cache.php / object-cache.php drop-ins.
	 *
	 * @param string $content File contents.
	 */
	private static function db_php_is_hostile( $content ) {
		if ( '' === $content ) {
			return false;
		}
		if ( false !== strpos( $content, 'MVN Safe' ) ) {
			return false;
		}
		if ( preg_match( '/\b(?:eval|assert|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content )
			&& preg_match( '/base64_decode|\$_(?:POST|GET|REQUEST|COOKIE)|create_function/i', $content ) ) {
			return true;
		}
		if ( preg_match( '/auto_prepend_file|zonal-runner|xdav|mu-plugins.*file_put_contents|\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}/i', $content ) ) {
			return true;
		}
		if ( substr_count( $content, '\\x' ) > 80 && ! preg_match( '/wpdb|DB_HOST|mysqli_connect|hyperdb|Query Monitor|WP_Object_Cache/i', $content ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Try to clear immutable / system attributes before unlink.
	 *
	 * @param string $abs Absolute path.
	 */
	private static function try_clear_file_attrs( $abs ) {
		if ( ! is_string( $abs ) || '' === $abs || ! is_file( $abs ) ) {
			return;
		}
		if ( function_exists( 'escapeshellarg' ) && ( function_exists( 'exec' ) || function_exists( 'shell_exec' ) ) ) {
			$escaped = escapeshellarg( $abs );
			$cmds    = array();
			if ( defined( 'PHP_OS_FAMILY' ) && 'Windows' === PHP_OS_FAMILY ) {
				$cmds[] = 'attrib -R -S -H ' . $escaped;
			} else {
				$cmds[] = 'chattr -i ' . $escaped . ' 2>/dev/null';
				$cmds[] = 'chattr -a ' . $escaped . ' 2>/dev/null';
			}
			foreach ( $cmds as $cmd ) {
				if ( function_exists( 'exec' ) ) {
					@exec( $cmd );
				} else {
					@shell_exec( $cmd );
				}
			}
		}
		@chmod( $abs, 0644 );
	}

	/**
	 * Resolve a site-relative path while respecting a custom WP_CONTENT_DIR.
	 *
	 * @param string $rel Relative path.
	 * @return string|false
	 */
	private static function resolve_rel_path( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
			return false;
		}
		if ( 0 === strpos( $rel, 'wp-content/' ) ) {
			return rtrim( WP_CONTENT_DIR, '/\\' ) . '/' . substr( $rel, strlen( 'wp-content/' ) );
		}
		return mvn_abs_path( $rel );
	}

	/**
	 * Try to set the immutable attribute so malware cannot overwrite our stub.
	 *
	 * @param string $abs Absolute path.
	 */
	private static function try_set_immutable( $abs ) {
		if ( ! is_string( $abs ) || '' === $abs || ! is_file( $abs ) ) {
			return;
		}
		if ( ( defined( 'PHP_OS_FAMILY' ) && 'Windows' === PHP_OS_FAMILY )
			|| ! function_exists( 'escapeshellarg' )
			|| ( ! function_exists( 'exec' ) && ! function_exists( 'shell_exec' ) ) ) {
			return; // no chattr on Windows dev; host is Linux.
		}
		$cmd = 'chattr +i ' . escapeshellarg( $abs ) . ' 2>/dev/null';
		if ( function_exists( 'exec' ) ) {
			@exec( $cmd );
		} elseif ( function_exists( 'shell_exec' ) ) {
			@shell_exec( $cmd );
		}
		$manifest = mvn_state_read( 'immutable_manifest', array( 'files' => array() ) );
		$manifest['files'][ mvn_normalize_path( $abs ) ] = array(
			'locked_at' => gmdate( 'c' ),
			'sha256'    => @hash_file( 'sha256', $abs ),
		);
		mvn_state_write( 'immutable_manifest', $manifest );
	}

	/**
	 * Release only immutable files recorded by MVN.
	 *
	 * @return array{released:string[],errors:string[]}
	 */
	public static function release_immutable_locks() {
		$out      = array( 'released' => array(), 'errors' => array() );
		$manifest = mvn_state_read( 'immutable_manifest', array( 'files' => array() ) );
		foreach ( isset( $manifest['files'] ) ? $manifest['files'] : array() as $abs => $info ) {
			if ( false === mvn_safe_write_path( $abs ) ) {
				$out['errors'][] = $abs . ': outside allowed roots';
				continue;
			}
			self::try_clear_file_attrs( $abs );
			$out['released'][] = mvn_rel_path( $abs );
		}
		mvn_state_delete( 'immutable_manifest' );
		return $out;
	}

	/**
	 * Overwrite a PHP file with a harmless stub (defeats cached auto_prepend / open handles).
	 *
	 * @param string $abs  Absolute path.
	 * @param bool   $lock Attempt to lock immutable afterwards.
	 * @return bool True if neutralized.
	 */
	public static function neutralize_php_file( $abs, $lock = false ) {
		if ( ! is_string( $abs ) || '' === $abs || ! is_file( $abs ) ) {
			return false;
		}
		self::try_clear_file_attrs( $abs );
		@chmod( $abs, 0644 );
		$stub = "<?php\n/* Neutralized by Mohtavanegar Antivirus (MVN Safe stub). */\n";
		$ok   = mvn_atomic_write( $abs, $stub, 0644 );
		if ( $ok && $lock ) {
			self::try_set_immutable( $abs );
		}
		return $ok;
	}

	/**
	 * Parse auto_prepend/append targets from ini/htaccess content, resolved against $base_dir.
	 *
	 * @param string $content  File contents.
	 * @param string $base_dir Directory of the ini/htaccess file.
	 * @return string[] Absolute target paths.
	 */
	private static function parse_prepend_targets( $content, $base_dir ) {
		$targets = array();
		if ( '' === (string) $content ) {
			return $targets;
		}
		if ( preg_match_all( '/auto_(?:pre|ap)pend_file\s*[=\s]\s*["\']?([^"\'\r\n;]+)/i', $content, $m ) ) {
			foreach ( $m[1] as $raw ) {
				$raw = trim( $raw );
				if ( '' === $raw || 'none' === strtolower( $raw ) ) {
					continue;
				}
				$abs = $raw;
				if ( ! preg_match( '#^(?:/|[A-Za-z]:[\\\\/])#', $raw ) ) {
					$abs = rtrim( $base_dir, '/\\' ) . '/' . ltrim( $raw, '/\\' );
				}
				$real = @realpath( $abs );
				$targets[] = $real ? $real : $abs;
			}
		}
		return array_values( array_unique( $targets ) );
	}

	/**
	 * Require a path IoC or at least three independent behavior signals before deletion.
	 *
	 * @param string $path Candidate file.
	 * @return bool
	 */
	private static function file_has_confirmed_ioc( $path ) {
		$name = basename( $path );
		if ( preg_match( '/zonal|xdav|security[-_]?helper|^\\.?[a-f0-9]{8,16}\\.(?:php|phtml|zip)$/i', $name ) ) {
			return true;
		}
		if ( ! is_file( $path ) || filesize( $path ) > 4 * MB_IN_BYTES ) {
			return false;
		}
		$content = (string) @file_get_contents( $path );
		if ( self::is_mvn_safe_dropin( $path, $content ) ) {
			return false;
		}
		$signals  = preg_match( '/(?:eval|assert|system|shell_exec|passthru)\s*\(/i', $content ) ? 1 : 0;
		$signals += preg_match( '/(?:base64_decode|gzinflate|str_rot13|pack)\s*\(/i', $content ) ? 1 : 0;
		$signals += preg_match( '/(?:file_put_contents|fwrite|copy|rename)\s*\(/i', $content ) ? 1 : 0;
		$signals += preg_match( '/auto_prepend|mu-plugins|db\.php|zonal|xdav/i', $content ) ? 1 : 0;
		$signals += preg_match( '/\$_(?:POST|GET|REQUEST|COOKIE)\b/i', $content ) ? 1 : 0;
		return $signals >= 3;
	}

	/**
	 * Neutralize the auto_prepend chain: stub+lock the prepend target(s), empty+lock the ini.
	 *
	 * PHP caches .user.ini for up to user_ini.cache_ttl (300s), so deleting it is not enough.
	 * We instead point/keep the include at a harmless locked stub so cached directives are inert.
	 *
	 * @return array{neutralized:string[],errors:string[]}
	 */
	public static function neutralize_auto_prepend_chain() {
		$out  = array(
			'neutralized' => array(),
			'errors'      => array(),
		);
		$dirs = array( ABSPATH, WP_CONTENT_DIR, dirname( ABSPATH ) );
		$dirs = array_values( array_unique( array_filter( $dirs ) ) );
		$inis = array();
		foreach ( $dirs as $d ) {
			foreach ( array( '.user.ini', 'user.ini', 'php.ini', '.htaccess' ) as $name ) {
				$p = rtrim( $d, '/\\' ) . '/' . $name;
				if ( is_file( $p ) ) {
					$inis[ $p ] = true;
				}
			}
		}
		foreach ( array_keys( $inis ) as $ini ) {
			$content = (string) @file_get_contents( $ini );
			if ( false !== strpos( $content, 'MVN Safe' ) ) {
				continue;
			}
			$targets = self::parse_prepend_targets( $content, dirname( $ini ) );
			$malicious_chain = false;
			foreach ( $targets as $target ) {
				$suspicious_path = (bool) preg_match( '/zonal|xdav|security[-_]?helper|[a-f0-9]{8,16}\.php/i', $target );
				if ( is_file( $target ) && self::file_has_confirmed_ioc( $target ) ) {
					$malicious_chain = true;
					if ( self::neutralize_php_file( $target, true ) ) {
						$out['neutralized'][] = mvn_rel_path( $target ) . ' (prepend target — stub+lock)';
					}
				} elseif ( ! is_file( $target ) && $suspicious_path ) {
					$malicious_chain = true;
					// Create harmless locked stub so the cached directive stays inert.
					$dir = dirname( $target );
					if ( is_dir( $dir ) && mvn_atomic_write( $target, "<?php\n/* MVN Safe prepend stub. */\n", 0644 ) ) {
						self::try_set_immutable( $target );
						$out['neutralized'][] = mvn_rel_path( $target ) . ' (prepend stub created+lock)';
					}
				}
			}
			if ( ! $malicious_chain ) {
				continue;
			}
			$base = basename( $ini );
			$pattern = '.htaccess' === $base
				? '/^\s*php_(?:value|flag)\s+auto_(?:pre|ap)pend_file.*(?:\R|$)/im'
				: '/^\s*auto_(?:pre|ap)pend_file\s*=.*(?:\R|$)/im';
			$clean = preg_replace( $pattern, '', $content );
			self::try_clear_file_attrs( $ini );
			if ( is_string( $clean ) && $clean !== $content && mvn_atomic_write( $ini, $clean, 0644 ) ) {
				@chmod( $ini, 0644 );
				self::try_set_immutable( $ini );
				$out['neutralized'][] = mvn_rel_path( $ini ) . ' (malicious prepend removed+lock)';
			} else {
				$out['errors'][] = 'خنثی‌سازی ناموفق: ' . mvn_rel_path( $ini );
			}
		}
		return $out;
	}

	/**
	 * Remove WP-Cron events whose hook/args reference the malware family (reinfection scheduler).
	 *
	 * @return string[] Removed hook labels.
	 */
	public static function purge_malicious_cron() {
		$removed = array();
		$cron    = get_option( 'cron' );
		if ( ! is_array( $cron ) ) {
			return $removed;
		}
		$needle = '/zonal|xdav|security[-_]?helper|wp[-_]?compat|(?:^|[\/\\\\])[a-f0-9]{8,16}\.php|auto_prepend/i';
		$changed = false;
		foreach ( $cron as $ts => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}
			foreach ( $hooks as $hook => $events ) {
				$blob = $hook . ' ' . wp_json_encode( $events );
				if ( 'version' === $hook || ! preg_match( $needle, (string) $blob ) ) {
					continue;
				}
				unset( $cron[ $ts ][ $hook ] );
				$removed[] = (string) $hook;
				$changed   = true;
				if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
					@wp_clear_scheduled_hook( $hook );
				}
			}
			if ( empty( $cron[ $ts ] ) ) {
				unset( $cron[ $ts ] );
			}
		}
		if ( $changed ) {
			MVN_Quarantine::store_text(
				'db:options:cron',
				wp_json_encode( get_option( 'cron' ) ),
				array( 'reason' => 'pre-cron-remediation-snapshot' )
			);
			update_option( 'cron', $cron );
			mvn_invalidate_runtime_caches();
		}
		return array_values( array_unique( array_filter( $removed ) ) );
	}

	/**
	 * Hunt reinfection droppers across wp-content (bounded) and neutralize+delete them.
	 *
	 * A dropper is a PHP file that writes db.php / mu-plugins / hex shells / advanced-cache
	 * on each request. It is the source that keeps recreating IoCs.
	 *
	 * @param int $max_files Scan cap to avoid timeouts.
	 * @return array{neutralized:string[],errors:string[]}
	 */
	public static function hunt_reinfection_sources( $max_files = 20000 ) {
		$out = array(
			'neutralized' => array(),
			'errors'      => array(),
		);
		$root = WP_CONTENT_DIR;
		if ( ! is_dir( $root ) ) {
			return $out;
		}
		$self_dir = defined( 'MVN_PLUGIN_DIR' ) ? rtrim( str_replace( '\\', '/', MVN_PLUGIN_DIR ), '/' ) : '';
		$data_dir = str_replace( '\\', '/', mvn_data_dir() );
		$write_fn = '/\b(?:file_put_contents|fwrite|fputs|fopen|copy|rename|move_uploaded_file)\s*\(/i';
		$target_re = '/mu-plugins|db\.php|advanced-cache|object-cache|\.user\.ini|auto_prepend|zonal|xdav|[a-f0-9]{8,16}\.(?:php|zip)/i';
		$evasion   = '/eval\s*\(|assert\s*\(|gzinflate\s*\(|gzuncompress\s*\(|str_rot13\s*\(|base64_decode\s*\(|create_function\s*\(|\$[a-z_]+\s*\(\s*\$/i';
		$count = 0;
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( \Exception $e ) {
			$out['errors'][] = 'اسکن dropper ناموفق: ' . $e->getMessage();
			return $out;
		}
		foreach ( $it as $file ) {
			if ( $count >= $max_files ) {
				break;
			}
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = str_replace( '\\', '/', $file->getPathname() );
			if ( ( '' !== $self_dir && 0 === strpos( $path, $self_dir ) )
				|| 0 === strpos( $path, $data_dir ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'php8', 'inc', 'suspected' ), true ) ) {
				continue;
			}
			$count++;
			$size = $file->getSize();
			if ( $size < 40 || $size > 3145728 ) { // 3MB cap.
				continue;
			}
			$base = basename( $path );
			if ( 0 === strpos( $base, 'zz-mvn-kill-' ) ) {
				continue;
			}
			$raw = (string) @file_get_contents( $path );
			if ( '' === $raw || false !== strpos( $raw, 'MVN Safe' ) ) {
				continue;
			}
			$rel_in_uploads = ( false !== strpos( $path, '/uploads/' ) );
			$has_write      = (bool) preg_match( $write_fn, $raw );
			// Strong signals (low false-positive) — legit cache plugins won't match these.
			$strong_name = (bool) preg_match( '/zonal[-_]?runner|xdav[-_]?tracker|security[-_]?helper/i', $raw );
			$hex_write   = $has_write && preg_match( '/[a-f0-9]{8,16}\.(?:php|zip)/i', $raw );
			$obf_write   = $has_write && preg_match( $target_re, $raw ) && preg_match( $evasion, $raw );
			$upload_shell = $rel_in_uploads && preg_match( '/<\?php/i', $raw ) && preg_match( $evasion, $raw );
			$is_dropper   = ( $strong_name && ( $has_write || $rel_in_uploads ) )
				|| $hex_write || $obf_write || $upload_shell;
			if ( ! $is_dropper ) {
				continue;
			}
			$rel = mvn_rel_path( $path );
			$del  = self::force_delete_file( $rel, 'reinfection_dropper' );
			if ( is_wp_error( $del ) ) {
				// force_delete_file preserves evidence first and neutralizes before unlink.
				$out['neutralized'][] = $rel . ' (خنثی شد ولی حذف قفل بود)';
				$out['errors'][]      = $del->get_error_message();
			} else {
				$out['neutralized'][] = $rel;
			}
		}
		return $out;
	}

	/**
	 * Force-delete a file: clear attrs → quarantine evidence → neutralize → unlink/rename; verify gone.
	 *
	 * @param string $rel Relative path.
	 * @param string $reason Quarantine reason.
	 * @return true|WP_Error
	 */
	public static function force_delete_file( $rel, $reason = 'malware_persistence' ) {
		$abs = self::resolve_rel_path( $rel );
		if ( ! $abs || ! is_file( $abs ) ) {
			return true;
		}
		self::try_clear_file_attrs( $abs );
		@chmod( $abs, 0644 );
		// Preserve the original evidence before overwriting executable content.
		MVN_Quarantine::store( $rel, array( 'reason' => $reason ) );
		// Neutralize executable content first so a locked/cached-include copy is inert.
		$ext = strtolower( pathinfo( $abs, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'php8', 'inc' ), true ) ) {
			@file_put_contents( $abs, "<?php\n/* removed by MVN */\n" );
		}
		if ( @unlink( $abs ) && ! is_file( $abs ) ) {
			return true;
		}
		$kill_root = mvn_data_dir() . '/kill';
		if ( ! is_dir( $kill_root ) ) {
			wp_mkdir_p( $kill_root );
		}
		$dest = $kill_root . '/' . basename( $abs ) . '-' . gmdate( 'YmdHis' ) . '-' . substr( md5( $abs . wp_rand() ), 0, 6 );
		if ( @rename( $abs, $dest ) ) {
			@chmod( $dest, 0644 );
			@unlink( $dest );
			if ( ! is_file( $abs ) ) {
				return true;
			}
		}
		$alt = $abs . '.__mvn_dead_' . gmdate( 'YmdHis' );
		if ( @rename( $abs, $alt ) ) {
			@unlink( $alt );
			if ( ! is_file( $abs ) ) {
				return true;
			}
		}
		if ( is_file( $abs ) ) {
			return new WP_Error(
				'force_unlink_fail',
				'حذف قفل‌شده ناموفق: ' . $rel . ' — از File Manager تیک Trash را بردارید یا با SSH: chattr -i && rm -f'
			);
		}
		return true;
	}

	/**
	 * db.php is never considered safe to keep (policy: block all wp-content/db.php).
	 *
	 * @param string $rel Relative path.
	 */
	public static function is_safe_db_rel( $rel ) {
		return false;
	}

	/**
	 * Delete discovered root/MU IoCs (including any db.php).
	 *
	 * @return array{deleted:string[],errors:string[]}
	 */
	public static function purge_discovered_iocs() {
		$out = array(
			'deleted' => array(),
			'errors'  => array(),
		);
		foreach ( self::discover_wpcontent_root_iocs() as $rel ) {
			if ( 'wp-content/advanced-cache.php' === $rel ) {
				if ( self::is_mvn_safe_dropin( (string) self::resolve_rel_path( $rel ) ) ) {
					continue;
				}
			}
			$ok = self::force_delete_file( $rel, 'wpcontent_root_ioc' );
			if ( is_wp_error( $ok ) ) {
				$out['errors'][] = $ok->get_error_message();
			} else {
				$out['deleted'][] = $rel;
			}
		}
		return $out;
	}

	/**
	 * Remove cache/wpo-cache staging dirs and db.php; place blockers so they cannot be recreated.
	 *
	 * @return array{deleted:string[],errors:string[]}
	 */
	public static function empty_cache_staging_dirs() {
		$out = array(
			'deleted' => array(),
			'errors'  => array(),
		);
		if ( class_exists( 'MVN_Path_Blocker', false ) ) {
			$r = MVN_Path_Blocker::enforce();
			$out['deleted'] = array_merge( $r['removed'], $r['blocked'] );
			$out['errors']  = $r['errors'];
			return $out;
		}
		foreach ( array( 'cache', 'wpo-cache' ) as $name ) {
			$dir = WP_CONTENT_DIR . '/' . $name;
			if ( is_dir( $dir ) ) {
				self::empty_directory_contents( $dir );
				@rmdir( $dir );
				$out['deleted'][] = 'wp-content/' . $name . '/';
			}
		}
		$db = WP_CONTENT_DIR . '/db.php';
		if ( is_file( $db ) ) {
			self::try_clear_file_attrs( $db );
			@chmod( $db, 0644 );
			if ( @unlink( $db ) ) {
				$out['deleted'][] = 'wp-content/db.php';
			}
		}
		return $out;
	}

	/**
	 * Delete files/dirs inside a directory without removing the directory itself.
	 *
	 * @param string $dir Absolute directory.
	 * @return int Removed entries.
	 */
	private static function empty_directory_contents( $dir ) {
		$count = 0;
		foreach ( scandir( $dir ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			if ( is_dir( $path ) ) {
				$it = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::CHILD_FIRST
				);
				foreach ( $it as $file ) {
					$file->isDir() ? @rmdir( $file->getPathname() ) : @unlink( $file->getPathname() );
					$count++;
				}
				if ( @rmdir( $path ) ) {
					$count++;
				}
			} elseif ( is_file( $path ) ) {
				self::try_clear_file_attrs( $path );
				if ( @unlink( $path ) ) {
					$count++;
				}
			}
		}
		return $count;
	}

	/**
	 * After purge: block cache/db.php recreation. Do NOT install db.php (even "safe").
	 * Only keep a no-op advanced-cache stub when WP_CACHE would otherwise fatal.
	 *
	 * @return array{safe_db:string,safe_ac:string,errors:string[]}
	 */
	public static function reinstall_safe_dropins() {
		$out = array(
			'safe_db' => '',
			'safe_ac' => '',
			'errors'  => array(),
		);
		// Policy: never leave wp-content/db.php — malware and our old stub both get blocked.
		if ( class_exists( 'MVN_Path_Blocker', false ) ) {
			$block = MVN_Path_Blocker::enforce();
			$out['errors'] = array_merge( $out['errors'], $block['errors'] );
		} else {
			$db = WP_CONTENT_DIR . '/db.php';
			if ( is_file( $db ) ) {
				self::try_clear_file_attrs( $db );
				@unlink( $db );
			}
		}
		if ( ( defined( 'WP_CACHE' ) && WP_CACHE ) || is_file( WP_CONTENT_DIR . '/advanced-cache.php' ) ) {
			$ac = self::install_safe_advanced_cache();
			if ( is_wp_error( $ac ) ) {
				$out['errors'][] = $ac->get_error_message();
			} elseif ( $ac ) {
				$out['safe_ac'] = $ac;
			}
		}
		return $out;
	}

	/**
	 * Neutralize early drop-ins (db.php / advanced-cache / object-cache) that reinfect before MU loads.
	 *
	 * @return array{deleted:string[],errors:string[],safe_db:string,safe_ac:string}
	 */
	public static function neutralize_early_dropins() {
		$out = array(
			'deleted' => array(),
			'errors'  => array(),
			'safe_db' => '',
			'safe_ac' => '',
		);
		$targets = array( 'wp-content/db.php', 'wp-content/advanced-cache.php' );
		$oc      = WP_CONTENT_DIR . '/object-cache.php';
		if ( is_file( $oc ) && ! self::is_mvn_safe_dropin( $oc ) ) {
			$oc_c = (string) @file_get_contents( $oc );
			if ( self::db_php_is_hostile( $oc_c )
				|| (bool) preg_grep( '/zonal|xdav|^\.?[a-f0-9]{6,16}\.php$/i', scandir( WP_CONTENT_DIR ) ?: array() ) ) {
				$targets[] = 'wp-content/object-cache.php';
			}
		}
		foreach ( $targets as $rel ) {
			$abs = self::resolve_rel_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			// Never keep db.php. Other drop-ins: keep only intentional MVN advanced-cache stub.
			if ( 'wp-content/db.php' !== $rel && self::is_mvn_safe_dropin( $abs ) ) {
				continue;
			}
			$ok = self::force_delete_file( $rel, 'early_dropin_neutralize' );
			if ( is_wp_error( $ok ) ) {
				$out['errors'][] = $ok->get_error_message();
			} else {
				$out['deleted'][] = $rel;
			}
		}
		if ( class_exists( 'MVN_Path_Blocker', false ) ) {
			$block         = MVN_Path_Blocker::enforce();
			$out['deleted'] = array_merge( $out['deleted'], $block['removed'] );
			$out['errors']  = array_merge( $out['errors'], $block['errors'] );
		}
		$need_safe = ! empty( $out['deleted'] )
			|| ( is_dir( WP_CONTENT_DIR . '/mu-plugins' )
				&& (bool) preg_grep( '/zonal|xdav/i', scandir( WP_CONTENT_DIR . '/mu-plugins' ) ?: array() ) );
		if ( $need_safe ) {
			$re = self::reinstall_safe_dropins();
			$out['safe_db'] = '';
			$out['safe_ac'] = $re['safe_ac'];
			$out['errors']  = array_merge( $out['errors'], $re['errors'] );
		}
		return $out;
	}

	/**
	 * Deprecated: never install db.php. Removes it and enforces path blockers.
	 *
	 * @return string Empty — no drop-in left behind.
	 */
	public static function install_safe_db_dropin() {
		if ( class_exists( 'MVN_Path_Blocker', false ) ) {
			MVN_Path_Blocker::enforce();
			return '';
		}
		$path = WP_CONTENT_DIR . '/db.php';
		if ( is_file( $path ) ) {
			self::try_clear_file_attrs( $path );
			@chmod( $path, 0644 );
			@unlink( $path );
		}
		return '';
	}

	/**
	 * Temporary no-op advanced-cache so WP_CACHE sites do not fatal after malware AC removal.
	 *
	 * @return string|WP_Error|'' Relative path or empty if not needed.
	 */
	public static function install_safe_advanced_cache() {
		$path = WP_CONTENT_DIR . '/advanced-cache.php';
		if ( is_file( $path ) && self::is_mvn_safe_dropin( $path ) ) {
			return 'wp-content/advanced-cache.php';
		}
		$expire = time() + ( 2 * DAY_IN_SECONDS );
		$code   = '<?php
/**
 * MVN Safe Cache — temporary stub after malware advanced-cache removal.
 * Safe to delete; auto-removes after TTL.
 */
if ( ! defined( \'ABSPATH\' ) ) { exit; }
if ( time() > ' . (int) $expire . ' ) {
	@unlink( __FILE__ );
}
';
		if ( false === @file_put_contents( $path, $code ) ) {
			return new WP_Error( 'safe_ac_write', 'نوشتن advanced-cache.php امن ناموفق بود.' );
		}
		@chmod( $path, 0644 );
		return 'wp-content/advanced-cache.php';
	}

	/**
	 * Whether plugin Name/Description/folder matches a known malware name pattern.
	 *
	 * @param string $haystack Text to test.
	 * @return string|false Matched pattern label or false.
	 */
	public static function name_pattern_match( $haystack ) {
		$haystack = (string) $haystack;
		if ( '' === $haystack ) {
			return false;
		}
		foreach ( self::malware_name_patterns() as $pattern ) {
			if ( @preg_match( $pattern, $haystack ) ) {
				return $pattern;
			}
		}
		return false;
	}

	/**
	 * Structural audit at scan start: IoC folders + plugins hidden via all_plugins.
	 *
	 * @param array $state Scan state by reference.
	 */
	public static function audit( &$state ) {
		self::audit_ioc_paths( $state );
		self::audit_name_patterns( $state );
		self::audit_persistence_droppers( $state );
		self::audit_hidden_via_filter( $state );
		self::audit_active_vs_disk( $state );
		self::audit_hidden_admins( $state );
	}

	/**
	 * Flag every known malware plugin path that exists on disk.
	 *
	 * @param array $state Scan state.
	 */
	private static function audit_ioc_paths( &$state ) {
		$dir = WP_PLUGIN_DIR;
		if ( ! is_dir( $dir ) ) {
			return;
		}

		foreach ( self::malware_slugs() as $slug ) {
			$folder = $dir . '/' . $slug;
			if ( ! is_dir( $folder ) ) {
				continue;
			}
			$main = self::find_plugin_bootstrap( $folder, $slug );
			$rel  = $main ? mvn_rel_path( $main ) : ( 'wp-content/plugins/' . $slug );
			self::add_ioc_finding(
				$state,
				$rel,
				'known_malware_plugin',
				'پلاگین بدافزار شناخته‌شده (IoC): ' . $slug,
				'پوشه «' . $slug . '» روی دیسک وجود دارد — خانواده xdav-tracker / بک‌دور مخفی.',
				is_file( $main ) ? @file_get_contents( $main ) : ''
			);
		}

		foreach ( self::malware_basenames() as $name ) {
			$abs = $dir . '/' . $name;
			if ( ! is_file( $abs ) ) {
				continue;
			}
			$content = @file_get_contents( $abs );
			self::add_ioc_finding(
				$state,
				'wp-content/plugins/' . $name,
				'known_malware_plugin',
				'فایل پلاگین بدافزار شناخته‌شده: ' . $name,
				'فایل تک‌فایلی مخرب در ریشه plugins.',
				is_string( $content ) ? $content : ''
			);
		}
	}

	/**
	 * Flag plugins whose Plugin Name / folder matches known fake-plugin name patterns
	 * (e.g. "Zonal Runner Tap" with a random folder slug).
	 *
	 * @param array $state Scan state.
	 */
	private static function audit_name_patterns( &$state ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$installed = get_plugins();
		$self      = mvn_self_plugin_slugs();
		if ( ! is_array( $installed ) ) {
			return;
		}

		foreach ( $installed as $file => $data ) {
			$folder = dirname( $file );
			$slug   = ( '.' === $folder ) ? basename( $file, '.php' ) : $folder;
			if ( in_array( $slug, $self, true ) ) {
				continue;
			}
			// Already covered by path IoC.
			if ( self::path_ioc_match( 'wp-content/plugins/' . $file ) ) {
				continue;
			}

			$name = isset( $data['Name'] ) ? (string) $data['Name'] : '';
			$desc = isset( $data['Description'] ) ? (string) $data['Description'] : '';
			$blob = $name . "\n" . $desc . "\n" . $slug . "\n" . $file;
			if ( ! self::name_pattern_match( $blob ) ) {
				continue;
			}

			$rel     = 'wp-content/plugins/' . $file;
			$abs     = WP_PLUGIN_DIR . '/' . $file;
			$content = is_file( $abs ) ? @file_get_contents( $abs ) : '';
			self::add_ioc_finding(
				$state,
				$rel,
				'known_malware_plugin',
				'پلاگین جعلی با نام مشکوک: ' . ( $name ? $name : $slug ),
				'نام/توضیح با الگوی بدافزار (مثل Zonal Runner Tap / xdav) مطابقت دارد — پوشه: ' . $slug,
				is_string( $content ) ? $content : ''
			);
		}
	}

	/**
	 * Flag mu-plugin loaders and upgrade droppers used for reinfection.
	 *
	 * @param array $state Scan state.
	 */
	private static function audit_persistence_droppers( &$state ) {
		foreach ( self::persistence_path_globs() as $rel ) {
			$abs = self::resolve_rel_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			$content = @file_get_contents( $abs );
			self::add_ioc_finding(
				$state,
				$rel,
				'malware_persistence_dropper',
				'فایل persistence بدافزار: ' . basename( $rel ),
				'بک‌آپ/دراپر شناخته‌شده برای بازگردانی پلاگین مخرب بعد از حذف.',
				is_string( $content ) ? $content : ''
			);
		}

		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
		if ( ! is_dir( $mu ) ) {
			return;
		}
		foreach ( scandir( $mu ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$abs = $mu . '/' . $entry;
			if ( ! is_file( $abs ) ) {
				continue;
			}
			if ( 0 === strpos( $entry, 'zz-mvn-kill-' ) ) {
				continue; // our temporary killer
			}
			// Imunify IoC: wp-??????-loader.php or 00-site-cache.php
			$hit = (bool) preg_match( '/^wp-[a-z0-9]{6}-loader\.php$/i', $entry )
				|| ( 0 === strcasecmp( $entry, '00-site-cache.php' ) )
				|| (bool) preg_match( '/zonal|xdav|security-helper|site-cache|maintenance/i', $entry );
			if ( ! $hit ) {
				$content_peek = (string) @file_get_contents( $abs );
				// Small dropper that restores plugins from upgrade/ or copies itself.
				$hit = strlen( $content_peek ) < 80000
					&& preg_match( '/(?:wp-maintenance\.tmp|copy\s*\(|rename\s*\(|WP_PLUGIN_DIR|all_plugins)/i', $content_peek )
					&& preg_match( '/(?:mkdir|file_put_contents|fwrite|unzip|Plugin_Upgrader)/i', $content_peek );
				if ( ! $hit ) {
					continue;
				}
			} else {
				$content_peek = (string) @file_get_contents( $abs );
			}

			$rel = 'wp-content/mu-plugins/' . $entry;
			self::add_ioc_finding(
				$state,
				$rel,
				'malware_persistence_dropper',
				'MU-plugin دراپر مشکوک: ' . $entry,
				'فایل must-use که بدون فعال‌سازی لود می‌شود — لایه persistence خانواده Hidden Admin / fake plugin.',
				$content_peek
			);
		}
	}

	/**
	 * Plugins present in get_plugins() but removed by all_plugins filter = actively hiding.
	 *
	 * @param array $state Scan state.
	 */
	private static function audit_hidden_via_filter( &$state ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$all = get_plugins();
		if ( ! is_array( $all ) || empty( $all ) ) {
			return;
		}

		$filtered = apply_filters( 'all_plugins', $all );
		if ( ! is_array( $filtered ) ) {
			$filtered = array();
		}

		$hidden = array_diff_key( $all, $filtered );
		$self   = mvn_self_plugin_slugs();

		foreach ( $hidden as $file => $data ) {
			$folder = dirname( $file );
			$slug   = ( '.' === $folder ) ? $file : $folder;
			if ( in_array( $slug, $self, true ) ) {
				continue;
			}
			$rel     = 'wp-content/plugins/' . $file;
			$abs     = WP_PLUGIN_DIR . '/' . $file;
			$content = is_file( $abs ) ? @file_get_contents( $abs ) : '';
			$name    = isset( $data['Name'] ) ? $data['Name'] : $slug;
			self::add_ioc_finding(
				$state,
				$rel,
				'hidden_plugin_filter',
				'پلاگین مخفی‌شده از لیست Plugins: ' . $name,
				'با فیلتر all_plugins از داشبورد پنهان شده — الگوی بک‌دور (xdav / security-helper).',
				is_string( $content ) ? $content : ''
			);
		}
	}

	/**
	 * Active plugins (raw DB) whose bootstrap file is missing or folder is orphan malware IoC.
	 *
	 * @param array $state Scan state.
	 */
	private static function audit_active_vs_disk( &$state ) {
		$active = self::raw_active_plugins();
		if ( empty( $active ) ) {
			return;
		}

		foreach ( $active as $file ) {
			$file = str_replace( '\\', '/', (string) $file );
			$abs  = WP_PLUGIN_DIR . '/' . $file;
			$rel  = 'wp-content/plugins/' . $file;
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				$slug = basename( $file, '.php' );
			}

			$ioc = self::path_ioc_match( $rel );
			if ( $ioc && is_file( $abs ) ) {
				$content = @file_get_contents( $abs );
				self::add_ioc_finding(
					$state,
					$rel,
					'known_malware_plugin',
					'پلاگین بدافزار فعال در active_plugins: ' . $ioc,
					'در option فعال است — حتی اگر در UI دیده نشود.',
					is_string( $content ) ? $content : ''
				);
			}
		}

		// Folders on disk that look like plugins but are not in get_plugins() (broken headers / droppers).
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$known = get_plugins();
		$known_folders = array();
		foreach ( array_keys( $known ) as $plugin_file ) {
			$folder = dirname( $plugin_file );
			if ( '.' !== $folder ) {
				$known_folders[ $folder ] = true;
			}
		}

		$dir = WP_PLUGIN_DIR;
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$self = mvn_self_plugin_slugs();
		foreach ( scandir( $dir ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry || ! is_dir( $dir . '/' . $entry ) ) {
				continue;
			}
			if ( in_array( $entry, $self, true ) ) {
				continue;
			}
			if ( isset( $known_folders[ $entry ] ) ) {
				continue;
			}
			// Only flag if slug matches malware IoC or folder contains hide-self markers.
			$ioc = in_array( $entry, self::malware_slugs(), true );
			$boot = self::find_plugin_bootstrap( $dir . '/' . $entry, $entry );
			$content = ( $boot && is_file( $boot ) ) ? (string) @file_get_contents( $boot ) : '';
			$hide    = $content && preg_match( '/all_plugins|pre_user_query|views_users/i', $content )
				&& preg_match( '/unset\s*\(|array_diff|plugin_basename/i', $content );

			if ( ! $ioc && ! $hide ) {
				continue;
			}

			$rel = $boot ? mvn_rel_path( $boot ) : ( 'wp-content/plugins/' . $entry );
			self::add_ioc_finding(
				$state,
				$rel,
				$ioc ? 'known_malware_plugin' : 'orphan_stealth_plugin',
				$ioc ? ( 'پوشه بدافزار بدون هدر معتبر: ' . $entry ) : ( 'پلاگین یتیم با کد مخفی‌سازی: ' . $entry ),
				'پوشه روی دیسک هست ولی در get_plugins دیده نمی‌شود.',
				$content
			);
		}
	}

	/**
	 * Compare administrator count in SQL vs get_users (filtered) — ghost admin IoC.
	 *
	 * @param array $state Scan state.
	 */
	private static function audit_hidden_admins( &$state ) {
		$ghost = self::ghost_admin_rows();
		if ( empty( $ghost ) ) {
			return;
		}

		foreach ( $ghost as $row ) {
			$uid   = isset( $row['ID'] ) ? (int) $row['ID'] : 0;
			$login = isset( $row['user_login'] ) ? $row['user_login'] : (string) $uid;
			$rel   = 'db:users:' . $login . ':user_login';
			$hash  = md5( wp_json_encode( $row ) );
			if ( MVN_Scanner::add_finding(
				$state,
				array(
					'source'   => 'db',
					'table'    => 'users',
					'row_id'   => $uid,
					'column'   => 'user_login',
					'row_key'  => $login,
					'rel'      => $rel,
					'sig'      => 'db_ghost_admin',
					'label'    => 'ادمین مخفی (فقط در دیتابیس دیده می‌شود)',
					'severity' => 'critical',
					'detail'   => 'کاربر «' . $login . '» در SQL ادمین است ولی get_users آن را نشان نمی‌دهد — الگوی xdav / Zonal Runner / security-helper.',
					'action'   => 'db_review',
					'clean'    => 'none',
					'snippet'  => $login . ' <' . ( isset( $row['user_email'] ) ? $row['user_email'] : '' ) . '>',
				),
				isset( $row['user_login'] ) ? $row['user_login'] : '',
				$hash
			) ) {
				if ( ! isset( $state['stats']['critical'] ) ) {
					$state['stats']['critical'] = 0;
				}
				$state['stats']['critical']++;
				if ( ! isset( $state['stats']['db'] ) ) {
					$state['stats']['db'] = 0;
				}
				$state['stats']['db']++;
			}
		}
	}

	/**
	 * User IDs that truly have administrator role in usermeta (strict serialized check).
	 *
	 * @return int[]
	 */
	public static function sql_admin_ids() {
		global $wpdb;

		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';
		$rows    = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT user_id, meta_value FROM {$wpdb->usermeta}
				WHERE meta_key = %s AND meta_value LIKE %s",
				$cap_key,
				'%s:13:"administrator";b:1%'
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}

		$ids = array();
		foreach ( $rows as $row ) {
			$uid  = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			$caps = isset( $row['meta_value'] ) ? maybe_unserialize( $row['meta_value'] ) : null;
			if ( $uid && is_array( $caps ) && ! empty( $caps['administrator'] ) ) {
				$ids[] = $uid;
			}
		}
		return array_values( array_unique( $ids ) );
	}

	/**
	 * Administrator IDs visible through WordPress APIs (may be filtered by malware).
	 *
	 * @return int[]
	 */
	public static function visible_admin_ids() {
		$users = get_users(
			array(
				'role'        => 'administrator',
				'fields'      => 'ID',
				'number'      => -1,
				'count_total' => false,
			)
		);
		$ids = array();
		foreach ( (array) $users as $u ) {
			if ( is_object( $u ) && isset( $u->ID ) ) {
				$ids[] = (int) $u->ID;
			} else {
				$ids[] = (int) $u;
			}
		}
		return array_values( array_unique( array_filter( $ids ) ) );
	}

	/**
	 * Ghost admin user rows (in SQL as admin, missing from get_users).
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function ghost_admin_rows() {
		global $wpdb;

		$ghost_ids = self::ghost_admin_ids();
		if ( empty( $ghost_ids ) ) {
			return array();
		}

		$out = array();
		foreach ( $ghost_ids as $uid ) {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT ID, user_login, user_email, user_registered FROM {$wpdb->users} WHERE ID = %d",
					$uid
				),
				ARRAY_A
			);
			if ( ! empty( $row ) ) {
				$out[] = $row;
			}
		}
		return $out;
	}

	/**
	 * Ghost admin IDs (SQL admins not visible via get_users).
	 *
	 * @return int[]
	 */
	public static function ghost_admin_ids() {
		$sql = self::sql_admin_ids();
		$vis = self::visible_admin_ids();

		$ghost = array_diff( array_map( 'strval', $sql ), array_map( 'strval', $vis ) );
		$ghost = array_map( 'intval', array_values( $ghost ) );

		if ( empty( $ghost ) && count( $sql ) > ( count( $vis ) + 1 ) ) {
			$vis_map = array_fill_keys( array_map( 'intval', $vis ), true );
			foreach ( $sql as $uid ) {
				$uid = (int) $uid;
				if ( $uid && empty( $vis_map[ $uid ] ) ) {
					$ghost[] = $uid;
				}
			}
		}

		return array_values( array_unique( array_filter( $ghost ) ) );
	}

	/**
	 * Transactional ghost-admin remediation: dry-run -> demote (default) -> optional delete.
	 *
	 * @param int    $user_id User ID.
	 * @param string $mode    dry-run|demote|delete.
	 * @param string $confirm Token returned by dry-run; delete also needs DELETE:<login>.
	 * @return array|WP_Error
	 */
	public static function remediate_ghost_admin( $user_id, $mode = 'dry-run', $confirm = '' ) {
		global $wpdb;
		$user_id = (int) $user_id;
		if ( ! in_array( $user_id, self::ghost_admin_ids(), true ) ) {
			return new WP_Error( 'not_ghost', 'این کاربر در فهرست ghost admin تأییدشده نیست.' );
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return new WP_Error( 'missing_user', 'کاربر پیدا نشد.' );
		}
		$meta = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->usermeta} WHERE user_id = %d", $user_id ), ARRAY_A );
		$export = array(
			'user' => $user->data,
			'roles' => $user->roles,
			'caps' => $user->caps,
			'usermeta' => $meta,
			'exported_at' => gmdate( 'c' ),
		);
		if ( 'dry-run' === $mode ) {
			$token = wp_generate_password( 24, false, false );
			set_transient( 'mvn_ghost_confirm_' . $user_id, hash( 'sha256', $token ), 10 * MINUTE_IN_SECONDS );
			return array(
				'mode' => 'dry-run',
				'user_id' => $user_id,
				'login' => $user->user_login,
				'proposed' => 'demote',
				'confirm_token' => $token,
				'delete_phrase' => 'DELETE:' . $user->user_login,
				'export' => $export,
			);
		}
		$parts = explode( '|', (string) $confirm, 2 );
		$valid = get_transient( 'mvn_ghost_confirm_' . $user_id );
		if ( ! is_string( $valid ) || empty( $parts[0] ) || ! hash_equals( $valid, hash( 'sha256', $parts[0] ) ) ) {
			return new WP_Error( 'confirmation_required', 'dry-run و توکن تأیید معتبر لازم است.' );
		}
		$snapshot = MVN_Quarantine::store_text(
			'db:ghost-admin:' . $user_id,
			wp_json_encode( $export ),
			array( 'reason' => 'pre-ghost-admin-remediation', 'mode' => $mode )
		);
		if ( ! $snapshot ) {
			return new WP_Error( 'snapshot_failed', 'export کامل کاربر قبل از تغییر ناموفق بود.' );
		}
		if ( 'delete' === $mode ) {
			if ( 1 === $user_id ) {
				return new WP_Error( 'protected_user', 'حذف user ID 1 توسط افزونه هرگز مجاز نیست.' );
			}
			if ( empty( $parts[1] ) || ! hash_equals( 'DELETE:' . $user->user_login, $parts[1] ) ) {
				return new WP_Error( 'second_confirmation', 'برای حذف، تأیید دوم دقیق لازم است.' );
			}
			require_once ABSPATH . 'wp-admin/includes/user.php';
			$result = wp_delete_user( $user_id );
		} else {
			$user->set_role( 'subscriber' );
			if ( is_multisite() && is_super_admin( $user_id ) ) {
				revoke_super_admin( $user_id );
			}
			$result = true;
		}
		delete_transient( 'mvn_ghost_confirm_' . $user_id );
		return array( 'ok' => (bool) $result, 'mode' => $mode, 'snapshot' => $snapshot, 'user_id' => $user_id );
	}

	/**
	 * Purge known malware plugin folders/files and scrub active_plugins + tracker options.
	 *
	 * Multi-pass + shutdown re-clean: in-memory malware often rewrites IoCs after unlink
	 * in the same request; a second pass and shutdown callback undo that.
	 *
	 * @return array{deleted:string[],renamed:string[],options:string[],usermeta:string[],active_scrubbed:int,errors:string[],kill_mu:string,verify_after_reload:bool}
	 */
	public static function purge_known() {
		$result = array(
			'deleted'              => array(),
			'renamed'              => array(),
			'options'              => array(),
			'usermeta'             => array(),
			'active_scrubbed'      => 0,
			'errors'               => array(),
			'kill_mu'              => '',
			'verify_after_reload'  => true,
		);

		mvn_ensure_data_dirs();
		$result['prepend']     = array();
		$result['droppers']    = array();
		$result['cron_removed'] = array();

		// 0a) Break the auto_prepend chain FIRST — it runs before WP and reinfects every request.
		$chain = self::neutralize_auto_prepend_chain();
		$result['prepend'] = array_merge( $result['prepend'], $chain['neutralized'] );
		$result['errors']  = array_merge( $result['errors'], $chain['errors'] );

		// 0b) Neutralize early drop-ins.
		$early = self::neutralize_early_dropins();
		$result['deleted'] = array_merge( $result['deleted'], $early['deleted'] );
		$result['errors']  = array_merge( $result['errors'], $early['errors'] );
		if ( ! empty( $early['safe_db'] ) ) {
			$result['safe_db'] = $early['safe_db'];
		}
		if ( ! empty( $early['safe_ac'] ) ) {
			$result['safe_ac'] = $early['safe_ac'];
		}

		// 0c) Remove malicious scheduled events (reinfection scheduler).
		$result['cron_removed'] = self::purge_malicious_cron();

		// 1) Scrub active_plugins.
		$result['active_scrubbed'] = self::scrub_active_plugins();

		// 1b) Pass 1: root / MU IoCs (conditional skip of safe db only).
		$pass1 = self::purge_discovered_iocs();
		$result['deleted'] = array_merge( $result['deleted'], $pass1['deleted'] );
		$result['errors']  = array_merge( $result['errors'], $pass1['errors'] );

		// 1c) Hunt the reinfection dropper across wp-content (the source that recreates IoCs).
		$hunt = self::hunt_reinfection_sources();
		$result['droppers'] = array_merge( $result['droppers'], $hunt['neutralized'] );
		$result['errors']   = array_merge( $result['errors'], $hunt['errors'] );

		$cache = self::empty_cache_staging_dirs();
		$result['deleted'] = array_merge( $result['deleted'], $cache['deleted'] );
		$result['errors']  = array_merge( $result['errors'], $cache['errors'] );

		$dir              = WP_PLUGIN_DIR;
		$folders_to_purge = self::discover_malware_folders();

		// 2) Rename out of plugins, then quarantine/delete.
		foreach ( array_keys( $folders_to_purge ) as $slug ) {
			$folder = $dir . '/' . $slug;
			if ( ! is_dir( $folder ) ) {
				continue;
			}
			$moved = self::disable_plugin_folder( $folder, $slug );
			if ( is_wp_error( $moved ) ) {
				$result['errors'][] = $moved->get_error_message();
				$ok = self::quarantine_and_delete_tree( $folder, 'wp-content/plugins/' . $slug );
				if ( is_wp_error( $ok ) ) {
					$result['errors'][] = $ok->get_error_message();
				} else {
					$result['deleted'][] = 'wp-content/plugins/' . $slug . '/';
				}
				continue;
			}
			$result['renamed'][] = $moved['from'] . ' → ' . $moved['to'];
			$ok = self::quarantine_and_delete_tree( $moved['abs'], $moved['to'] );
			if ( is_wp_error( $ok ) ) {
				$result['errors'][]  = 'جابه‌جا شد ولی حذف کامل نشد: ' . $ok->get_error_message();
				$result['deleted'][] = $moved['from'] . ' (disabled)';
			} else {
				$result['deleted'][] = $moved['from'];
			}
		}

		foreach ( self::malware_basenames() as $name ) {
			$rel = 'wp-content/plugins/' . $name;
			if ( ! is_file( $dir . '/' . $name ) ) {
				continue;
			}
			$ok = self::force_delete_file( $rel, 'known_malware_plugin' );
			if ( is_wp_error( $ok ) ) {
				$result['errors'][] = $ok->get_error_message();
			} else {
				$result['deleted'][] = $rel;
			}
		}

		foreach ( self::persistence_path_globs() as $rel ) {
			$abs = self::resolve_rel_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			$ok = self::force_delete_file( $rel, 'malware_persistence_dropper' );
			if ( is_wp_error( $ok ) ) {
				$result['errors'][] = $ok->get_error_message();
			} else {
				$result['deleted'][] = $rel;
			}
		}

		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
		if ( is_dir( $mu ) ) {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $mu, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iterator as $file ) {
				$abs = $file->getPathname();
				if ( ! $file->isFile() || 0 === strpos( basename( $abs ), 'zz-mvn-kill-' ) || ! self::file_has_confirmed_ioc( $abs ) ) {
					continue;
				}
				$rel = mvn_rel_path( $abs );
				$ok  = self::force_delete_file( $rel, 'confirmed_mu_plugin_ioc' );
				if ( is_wp_error( $ok ) ) {
					$result['errors'][] = $ok->get_error_message();
				} else {
					$result['deleted'][] = $rel;
				}
			}
		}

		$result['options']  = self::delete_tracker_options();
		$result['usermeta'] = self::delete_tracker_usermeta();

		$kill = self::install_kill_mu_plugin( array_keys( $folders_to_purge ) );
		if ( is_wp_error( $kill ) ) {
			$result['errors'][] = $kill->get_error_message();
		} else {
			$result['kill_mu'] = $kill;
		}

		// Pass 2: undo same-request reinfection + reinstall safe drop-ins.
		$pass2 = self::purge_discovered_iocs();
		$result['deleted'] = array_merge( $result['deleted'], $pass2['deleted'] );
		$result['errors']  = array_merge( $result['errors'], $pass2['errors'] );
		$re = self::reinstall_safe_dropins();
		if ( ! empty( $re['safe_db'] ) ) {
			$result['safe_db'] = $re['safe_db'];
		}
		if ( ! empty( $re['safe_ac'] ) ) {
			$result['safe_ac'] = $re['safe_ac'];
		}
		$result['errors'] = array_merge( $result['errors'], $re['errors'] );

		// Shutdown: malware often rewrites on shutdown after our deletes.
		register_shutdown_function(
			static function () {
				if ( ! class_exists( 'MVN_Ghost_Plugins', false ) ) {
					return;
				}
				MVN_Ghost_Plugins::neutralize_auto_prepend_chain();
				MVN_Ghost_Plugins::purge_discovered_iocs();
				MVN_Ghost_Plugins::empty_cache_staging_dirs();
				MVN_Ghost_Plugins::reinstall_safe_dropins();
				$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
				if ( is_dir( $mu ) ) {
					foreach ( scandir( $mu ) ?: array() as $entry ) {
						if ( preg_match( '/zonal|xdav|security-helper/i', $entry ) ) {
							$abs = $mu . '/' . $entry;
							if ( is_file( $abs ) ) {
								MVN_Ghost_Plugins::force_delete_file( 'wp-content/mu-plugins/' . $entry, 'shutdown_reinfect' );
							}
						}
					}
				}
			}
		);

		if ( function_exists( 'opcache_reset' ) ) {
			@opcache_reset();
		}

		mvn_log(
			'Ghost plugin purge: deleted=' . count( $result['deleted'] )
			. ' renamed=' . count( $result['renamed'] )
			. ' prepend=' . count( $result['prepend'] )
			. ' droppers=' . count( $result['droppers'] )
			. ' cron=' . count( $result['cron_removed'] )
			. ' options=' . count( $result['options'] )
			. ' usermeta=' . count( $result['usermeta'] )
			. ' active_scrubbed=' . $result['active_scrubbed']
			. ' errors=' . count( $result['errors'] )
		);

		return $result;
	}

	/**
	 * Discover malware plugin folders on disk.
	 *
	 * @return array<string,true>
	 */
	private static function discover_malware_folders() {
		$folders = array();
		foreach ( self::malware_slugs() as $slug ) {
			$folders[ $slug ] = true;
		}

		$dir = WP_PLUGIN_DIR;
		if ( ! is_dir( $dir ) ) {
			return $folders;
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$self = mvn_self_plugin_slugs();
		foreach ( (array) get_plugins() as $file => $data ) {
			$folder = dirname( $file );
			$slug   = ( '.' === $folder ) ? '' : $folder;
			if ( ! $slug || in_array( $slug, $self, true ) ) {
				continue;
			}
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : '';
			$desc = isset( $data['Description'] ) ? (string) $data['Description'] : '';
			if ( self::name_pattern_match( $name . "\n" . $desc . "\n" . $slug . "\n" . $file ) ) {
				$folders[ $slug ] = true;
			}
		}

		foreach ( scandir( $dir ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry || ! is_dir( $dir . '/' . $entry ) ) {
				continue;
			}
			if ( in_array( $entry, $self, true ) ) {
				continue;
			}
			if ( preg_match( '/zonal|xdav|security-helper|wp-compat|content-optimizer|flavor-sync/i', $entry ) ) {
				$folders[ $entry ] = true;
				continue;
			}
			$boot = self::find_plugin_bootstrap( $dir . '/' . $entry, $entry );
			if ( ! $boot || ! is_file( $boot ) ) {
				continue;
			}
			$header = (string) @file_get_contents( $boot, false, null, 0, 8192 );
			if ( self::name_pattern_match( $header . "\n" . $entry ) ) {
				$folders[ $entry ] = true;
			}
		}

		return $folders;
	}

	/**
	 * Move malware folder out of wp-content/plugins.
	 *
	 * @param string $abs  Absolute path.
	 * @param string $slug Slug.
	 * @return array{from:string,to:string,abs:string}|WP_Error
	 */
	private static function disable_plugin_folder( $abs, $slug ) {
		$kill_root = mvn_data_dir() . '/kill';
		if ( ! is_dir( $kill_root ) ) {
			wp_mkdir_p( $kill_root );
		}
		$dest = $kill_root . '/' . $slug . '-' . gmdate( 'YmdHis' ) . '-' . substr( md5( $abs . wp_rand() ), 0, 6 );
		if ( @rename( $abs, $dest ) ) {
			return array(
				'from' => 'wp-content/plugins/' . $slug . '/',
				'to'   => mvn_rel_path( $dest ),
				'abs'  => $dest,
			);
		}
		$alt = rtrim( $abs, '/\\' ) . '.__mvn_dead_' . gmdate( 'His' );
		if ( @rename( $abs, $alt ) ) {
			return array(
				'from' => 'wp-content/plugins/' . $slug . '/',
				'to'   => mvn_rel_path( $alt ),
				'abs'  => $alt,
			);
		}
		return new WP_Error( 'rename_fail', 'جابه‌جایی پوشه ناموفق (قفل فایل؟): wp-content/plugins/' . $slug );
	}

	/**
	 * One-shot MU-plugin that deletes reinfected malware at include time (before plugins_loaded).
	 *
	 * @param string[] $slugs Slugs.
	 * @return string|WP_Error
	 */
	private static function install_kill_mu_plugin( $slugs ) {
		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
		if ( ! is_dir( $mu ) && ! wp_mkdir_p( $mu ) ) {
			return new WP_Error( 'mu_mkdir', 'ساخت پوشه mu-plugins ناموفق بود.' );
		}

		$slugs  = array_values( array_unique( array_filter( array_map( 'strval', (array) $slugs ) ) ) );
		$slugs  = array_values( array_unique( array_merge( $slugs, array( 'zonal-runner-tap', 'xdav-tracker', 'wp-security-helper', 'wp-compat' ) ) ) );
		$export = var_export( $slugs, true );
		$ttl    = time() + ( 2 * DAY_IN_SECONDS );
		$name   = 'zz-mvn-kill-malware.php';
		// Cleanup runs at file top-level so it executes as soon as this MU is included
		// (after alphabetically-earlier malware MUs on first load; before plugins_loaded).
		$code   = '<?php
/**
 * Plugin Name: MVN One-Shot Malware Killer
 * Description: Auto-generated by Mohtavanegar Antivirus. Deletes reinfectors at MU load time.
 */
if ( ! defined( \'ABSPATH\' ) ) { exit; }
$__mvn_kill = static function () {
	$expire = ' . $ttl . ';
	$slugs  = ' . $export . ';
	$dir    = defined( \'WP_PLUGIN_DIR\' ) ? WP_PLUGIN_DIR : ( WP_CONTENT_DIR . \'/plugins\' );
	$content = WP_CONTENT_DIR;
	$mu = $content . \'/mu-plugins\';
	$still  = false;
	$self = __FILE__;
	$safe = static function ( $path ) {
		if ( ! is_file( $path ) ) { return false; }
		$head = (string) @file_get_contents( $path, false, null, 0, 256 );
		return false !== strpos( $head, \'MVN Safe\' ) || false !== strpos( $head, \'Neutralized by\' );
	};
	$rm = static function ( $path ) {
		if ( is_file( $path ) ) {
			@chmod( $path, 0644 );
			if ( function_exists( \'exec\' ) && function_exists( \'escapeshellarg\' ) ) { @exec( \'chattr -i \' . escapeshellarg( $path ) . \' 2>/dev/null\' ); }
			if ( ! @unlink( $path ) ) { @rename( $path, $path . \'.__mvn_dead\' ); }
			return;
		}
		if ( ! is_dir( $path ) ) { return; }
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $it as $file ) {
			$file->isDir() ? @rmdir( $file->getPathname() ) : @unlink( $file->getPathname() );
		}
		@rmdir( $path );
	};
	foreach ( array( \'db.php\', \'advanced-cache.php\', \'object-cache.php\' ) as $drop ) {
		$p = $content . \'/\' . $drop;
		if ( ! is_file( $p ) ) { continue; }
		if ( \'db.php\' === $drop ) { $rm( $p ); continue; }
		$raw = (string) @file_get_contents( $p );
		if ( false !== strpos( $raw, \'MVN Safe\' ) ) { continue; }
		$rm( $p );
	}
	foreach ( array( \'cache\', \'wpo-cache\' ) as $dirn ) {
		$dp = $content . \'/\' . $dirn;
		if ( is_dir( $dp ) ) { $rm( $dp ); }
		if ( ! is_dir( $dp ) && ! is_file( $dp ) ) {
			@file_put_contents( $dp, "# MVN Path Block — do not delete.\\n" );
		}
	}
	if ( is_dir( $mu ) ) {
		foreach ( @scandir( $mu ) ?: array() as $entry ) {
			if ( \'.\' === $entry || \'..\' === $entry || 0 === strpos( $entry, \'zz-mvn-kill-\' ) ) { continue; }
			if ( \'index.php\' === $entry ) { continue; }
			if ( preg_match( \'/zonal|xdav|security-helper|wp-[a-z0-9]{6}-loader/i\', $entry ) || preg_match( \'/\\.php$/i\', $entry ) ) {
				$rm( $mu . \'/\' . $entry );
			}
		}
		foreach ( @scandir( $mu ) ?: array() as $entry ) {
			if ( preg_match( \'/zonal|xdav/i\', $entry ) ) { $still = true; break; }
		}
	}
	if ( is_dir( $content ) ) {
		foreach ( @scandir( $content ) ?: array() as $entry ) {
			if ( preg_match( \'/^\\.?[a-f0-9]{6,16}\\.(?:php|zip)$/i\', $entry ) || in_array( $entry, array( \'.user.ini\', \'user.ini\' ), true ) ) {
				$path = $content . \'/\' . $entry;
				if ( $safe( $path ) ) { continue; }
				$rm( $path );
			}
		}
		foreach ( @scandir( $content ) ?: array() as $entry ) {
			if ( preg_match( \'/^\\.?[a-f0-9]{6,16}\\.(?:php|zip)$/i\', $entry ) || \'.user.ini\' === $entry ) {
				$still = true;
				break;
			}
		}
	}
	foreach ( array( dirname( $content ) . \'/.user.ini\', ABSPATH . \'.user.ini\' ) as $ini ) {
		if ( is_file( $ini ) && ! $safe( $ini ) ) { $rm( $ini ); }
	}
	if ( is_dir( $dir ) ) {
		$targets = array();
		foreach ( $slugs as $slug ) {
			if ( is_dir( $dir . \'/\' . $slug ) ) { $targets[] = $dir . \'/\' . $slug; }
		}
		foreach ( @scandir( $dir ) ?: array() as $entry ) {
			if ( \'.\' === $entry || \'..\' === $entry || ! is_dir( $dir . \'/\' . $entry ) ) { continue; }
			if ( preg_match( \'/zonal|xdav[-_]?tracker|security-helper/i\', $entry ) ) {
				$targets[] = $dir . \'/\' . $entry;
			}
		}
		foreach ( array_unique( $targets ) as $path ) { $rm( $path ); }
		foreach ( $slugs as $slug ) {
			if ( is_dir( $dir . \'/\' . $slug ) ) { $still = true; break; }
		}
	}
	if ( time() > $expire ) {
		@unlink( $self );
	}
};
$__mvn_kill();
if ( function_exists( \'add_action\' ) ) {
	add_action( \'plugins_loaded\', $__mvn_kill, 0 );
	add_action( \'shutdown\', $__mvn_kill, 999 );
}
';
		$abs = $mu . '/' . $name;
		if ( false === @file_put_contents( $abs, $code ) ) {
			return new WP_Error( 'mu_write', 'نوشتن MU-plugin قاتل ناموفق بود.' );
		}
		return 'wp-content/mu-plugins/' . $name;
	}

	/**
	 * Status snapshot for Repair UI.
	 *
	 * @return array<string,mixed>
	 */
	public static function status() {
		$ioc = array();
		foreach ( self::malware_slugs() as $slug ) {
			if ( is_dir( WP_PLUGIN_DIR . '/' . $slug ) ) {
				$ioc[] = 'wp-content/plugins/' . $slug . '/';
			}
		}
		foreach ( self::malware_basenames() as $name ) {
			if ( is_file( WP_PLUGIN_DIR . '/' . $name ) ) {
				$ioc[] = 'wp-content/plugins/' . $name;
			}
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all  = get_plugins();
		$self = mvn_self_plugin_slugs();
		foreach ( (array) $all as $file => $data ) {
			$folder = dirname( $file );
			$slug   = ( '.' === $folder ) ? basename( $file, '.php' ) : $folder;
			if ( in_array( $slug, $self, true ) ) {
				continue;
			}
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : '';
			$desc = isset( $data['Description'] ) ? (string) $data['Description'] : '';
			if ( self::name_pattern_match( $name . "\n" . $desc . "\n" . $slug . "\n" . $file ) ) {
				$label = 'wp-content/plugins/' . ( '.' === $folder ? $file : ( $folder . '/' ) );
				if ( ! in_array( $label, $ioc, true ) ) {
					$ioc[] = $label . ( $name ? ( ' [' . $name . ']' ) : '' );
				}
			}
		}

		// Also flag fuzzy folder names present on disk.
		if ( is_dir( WP_PLUGIN_DIR ) ) {
			foreach ( scandir( WP_PLUGIN_DIR ) ?: array() as $entry ) {
				if ( '.' === $entry || '..' === $entry || ! is_dir( WP_PLUGIN_DIR . '/' . $entry ) ) {
					continue;
				}
				if ( preg_match( '/zonal|xdav|security-helper/i', $entry ) ) {
					$label = 'wp-content/plugins/' . $entry . '/';
					if ( ! in_array( $label, $ioc, true ) ) {
						$ioc[] = $label;
					}
				}
			}
		}

		$persist     = array();
		$protections = array();
		foreach ( self::persistence_path_globs() as $rel ) {
			if ( is_file( (string) self::resolve_rel_path( $rel ) ) && ! in_array( $rel, $persist, true ) ) {
				$persist[] = $rel;
			}
		}
		foreach ( self::discover_wpcontent_root_iocs() as $rel ) {
			if ( ! in_array( $rel, $persist, true ) ) {
				$persist[] = $rel;
			}
		}
		foreach ( array( 'db.php', 'advanced-cache.php' ) as $drop ) {
			$abs = WP_CONTENT_DIR . '/' . $drop;
			if ( is_file( $abs ) && self::is_mvn_safe_dropin( $abs ) ) {
				$label = 'wp-content/' . $drop . ( 'db.php' === $drop
					? ' (db امن موقت MVN)'
					: ' (cache امن موقت MVN)' );
				if ( ! in_array( $label, $protections, true ) ) {
					$protections[] = $label;
				}
			}
		}
		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
		if ( is_dir( $mu ) ) {
			foreach ( scandir( $mu ) ?: array() as $entry ) {
				if ( 0 === strpos( $entry, 'zz-mvn-kill-' ) ) {
					$label = 'wp-content/mu-plugins/' . $entry . ' (قاتل موقت MVN)';
					if ( ! in_array( $label, $protections, true ) ) {
						$protections[] = $label;
					}
					continue;
				}
				if ( preg_match( '/^wp-[a-z0-9]{6}-loader\.php$/i', $entry )
					|| 0 === strcasecmp( $entry, '00-site-cache.php' )
					|| preg_match( '/zonal|xdav|security-helper/i', $entry ) ) {
					$rel = 'wp-content/mu-plugins/' . $entry;
					if ( ! in_array( $rel, $persist, true ) ) {
						$persist[] = $rel;
					}
				}
			}
		}

		$hidden   = array();
		$filtered = apply_filters( 'all_plugins', is_array( $all ) ? $all : array() );
		foreach ( array_diff_key( (array) $all, (array) $filtered ) as $file => $_data ) {
			$hidden[] = $file;
		}

		global $wpdb;
		$tracker = array();
		foreach ( self::malware_option_names() as $name ) {
			$exists = $wpdb->get_var( $wpdb->prepare( "SELECT option_id FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $name ) );
			if ( $exists ) {
				$tracker[] = $name;
			}
		}
		$like_rows = self::tracker_option_names();
		if ( is_array( $like_rows ) ) {
			foreach ( $like_rows as $n ) {
				if ( ! in_array( $n, $tracker, true ) && ! in_array( $n, mvn_db_protected_options(), true ) ) {
					$tracker[] = $n;
				}
			}
		}

		$ghost_ids = self::ghost_admin_ids();
		$samples   = array();
		foreach ( array_slice( $ghost_ids, 0, 5 ) as $uid ) {
			$login = $wpdb->get_var( $wpdb->prepare( "SELECT user_login FROM {$wpdb->users} WHERE ID = %d", $uid ) );
			if ( $login ) {
				$samples[] = $login;
			}
		}

		return array(
			'ioc_paths'          => $ioc,
			'persistence'        => array_values( array_unique( $persist ) ),
			'protections'        => array_values( array_unique( $protections ) ),
			'hidden_plugins'     => $hidden,
			'ghost_admins'       => count( $ghost_ids ),
			'ghost_admin_sample' => $samples,
			'tracker_options'    => $tracker,
			'sql_admins'         => count( self::sql_admin_ids() ),
			'visible_admins'     => count( self::visible_admin_ids() ),
		);
	}

	/**
	 * @param array  $state   Scan state.
	 * @param string $rel     Relative path.
	 * @param string $sig     Signature id.
	 * @param string $label   Label.
	 * @param string $detail  Detail.
	 * @param string $content File content for confidence/snippet.
	 */
	private static function add_ioc_finding( &$state, $rel, $sig, $label, $detail, $content = '' ) {
		$hash = is_string( $content ) && '' !== $content ? md5( $content ) : md5( $rel . $sig );
		if ( ! MVN_Scanner::add_finding(
			$state,
			array(
				'rel'      => $rel,
				'sig'      => $sig,
				'label'    => $label,
				'severity' => 'critical',
				'detail'   => $detail,
				'action'   => 'quarantine_delete',
				'snippet'  => is_string( $content ) ? substr( preg_replace( '/\s+/', ' ', $content ), 0, 180 ) : '',
				'source'   => 'ghost',
			),
			is_string( $content ) ? $content : '',
			$hash
		) ) {
			return;
		}
		if ( ! isset( $state['stats']['critical'] ) ) {
			$state['stats']['critical'] = 0;
		}
		$state['stats']['critical']++;
		if ( ! isset( $state['stats']['ghost'] ) ) {
			$state['stats']['ghost'] = 0;
		}
		$state['stats']['ghost']++;
	}

	/**
	 * @param string $folder Absolute folder.
	 * @param string $slug   Folder slug.
	 * @return string|false Absolute bootstrap path.
	 */
	private static function find_plugin_bootstrap( $folder, $slug ) {
		$candidates = array(
			$folder . '/' . $slug . '.php',
			$folder . '/index.php',
			$folder . '/plugin.php',
		);
		foreach ( $candidates as $c ) {
			if ( is_file( $c ) ) {
				return $c;
			}
		}
		foreach ( scandir( $folder ) ?: array() as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$abs = $folder . '/' . $entry;
			if ( is_file( $abs ) && 'php' === strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) ) ) {
				return $abs;
			}
		}
		return false;
	}

	/**
	 * Raw active_plugins from DB (bypasses object-cache filters when possible).
	 *
	 * @return string[]
	 */
	private static function raw_active_plugins() {
		global $wpdb;
		$raw = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name = 'active_plugins' LIMIT 1" );
		if ( ! is_string( $raw ) || '' === $raw ) {
			$opt = get_option( 'active_plugins', array() );
			return is_array( $opt ) ? $opt : array();
		}
		$val = maybe_unserialize( $raw );
		return is_array( $val ) ? $val : array();
	}

	/**
	 * Remove malware plugin entries from active_plugins.
	 *
	 * @return int Number removed.
	 */
	private static function scrub_active_plugins() {
		$active = self::raw_active_plugins();
		if ( empty( $active ) ) {
			return 0;
		}
		$slugs = self::malware_slugs();
		$bases = self::malware_basenames();
		$kept  = array();
		$removed = 0;

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$installed = (array) get_plugins();

		foreach ( $active as $file ) {
			$file_n = str_replace( '\\', '/', (string) $file );
			$drop   = false;
			foreach ( $bases as $b ) {
				if ( 0 === strcasecmp( $file_n, $b ) ) {
					$drop = true;
					break;
				}
			}
			if ( ! $drop ) {
				foreach ( $slugs as $slug ) {
					if ( 0 === strpos( $file_n, $slug . '/' ) || $file_n === $slug ) {
						$drop = true;
						break;
					}
				}
			}
			if ( ! $drop && isset( $installed[ $file ] ) ) {
				$data = $installed[ $file ];
				$name = isset( $data['Name'] ) ? (string) $data['Name'] : '';
				$desc = isset( $data['Description'] ) ? (string) $data['Description'] : '';
				if ( self::name_pattern_match( $name . "\n" . $desc . "\n" . $file_n ) ) {
					$drop = true;
				}
			}
			if ( $drop ) {
				$removed++;
			} else {
				$kept[] = $file;
			}
		}
		if ( $removed > 0 ) {
			update_option( 'active_plugins', array_values( $kept ) );
		}
		return $removed;
	}

	/**
	 * Delete tracker options used by the malware family.
	 *
	 * @return string[] Deleted option names.
	 */
	private static function delete_tracker_options() {
		global $wpdb;
		$deleted = array();
		$names   = self::malware_option_names();
		$extra   = self::tracker_option_names();
		if ( is_array( $extra ) ) {
			$names = array_unique( array_merge( $names, $extra ) );
		}
		foreach ( $names as $name ) {
			if ( in_array( $name, mvn_db_protected_options(), true ) ) {
				continue;
			}
			$row = $wpdb->get_row(
				$wpdb->prepare( "SELECT option_id, option_name, option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $name ),
				ARRAY_A
			);
			if ( empty( $row ) ) {
				continue;
			}
			MVN_Quarantine::store_text(
				'db:options:' . $name,
				wp_json_encode( array( 'option_name' => $name, 'option_value' => $row['option_value'] ) ),
				array( 'reason' => 'malware-tracker-option' )
			);
			$wpdb->delete( $wpdb->options, array( 'option_id' => (int) $row['option_id'] ), array( '%d' ) );
			$deleted[] = $name;
		}
		return $deleted;
	}

	/**
	 * Enumerate all tracker-like options with keyset pagination.
	 *
	 * @return string[]
	 */
	private static function tracker_option_names() {
		global $wpdb;
		$names = array();
		$last  = 0;
		do {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_id, option_name FROM {$wpdb->options}
					WHERE option_id > %d AND (
						option_name LIKE '%%xdav%%'
						OR option_name LIKE '%%security_helper%%'
						OR option_name LIKE '%%security-helper%%'
						OR option_name LIKE '%%zonal%%runner%%'
						OR option_name LIKE '%%zonal_runner%%'
					)
					ORDER BY option_id ASC LIMIT 500",
					$last
				),
				ARRAY_A
			);
			foreach ( (array) $rows as $row ) {
				$last    = max( $last, (int) $row['option_id'] );
				$names[] = $row['option_name'];
			}
		} while ( count( (array) $rows ) === 500 );
		return array_values( array_unique( $names ) );
	}

	/**
	 * Delete usermeta keys used by Hidden Admin Toolkit family (Imunify IoCs).
	 *
	 * @return string[] Deleted "user_id:meta_key" labels.
	 */
	private static function delete_tracker_usermeta() {
		global $wpdb;
		$keys = array(
			'_wp_ui_render_cfg',
			'_wp_cache_hash',
			'_wps_sig',
			'_sys_token',
			'_bk_hash',
			'_adm_key',
			'_wp_sys_hash',
			'_stk_sig',
		);
		$deleted = array();
		foreach ( $keys as $key ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT umeta_id, user_id, meta_key, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s",
					$key
				),
				ARRAY_A
			);
			if ( empty( $rows ) ) {
				continue;
			}
			foreach ( $rows as $row ) {
				MVN_Quarantine::store_text(
					'db:usermeta:' . $row['user_id'] . '/' . $key,
					wp_json_encode( $row ),
					array( 'reason' => 'malware-tracker-usermeta' )
				);
				$wpdb->delete( $wpdb->usermeta, array( 'umeta_id' => (int) $row['umeta_id'] ), array( '%d' ) );
				$deleted[] = $row['user_id'] . ':' . $key;
			}
		}
		return $deleted;
	}

	/**
	 * Quarantine PHP files then recursively delete a malware plugin directory.
	 *
	 * @param string $abs Absolute folder.
	 * @param string $rel Relative folder prefix.
	 * @return true|WP_Error
	 */
	private static function quarantine_and_delete_tree( $abs, $rel ) {
		$files = mvn_list_files( $abs, 5000 );
		foreach ( $files as $file_rel ) {
			$file_abs = mvn_abs_path( $file_rel );
			if ( ! $file_abs || ! is_file( $file_abs ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $file_abs, PATHINFO_EXTENSION ) );
			if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'php8', 'inc', 'js' ), true ) ) {
				MVN_Quarantine::store( $file_rel, array( 'reason' => 'known_malware_plugin' ) );
			}
		}
		self::rrmdir( $abs );
		if ( is_dir( $abs ) ) {
			return new WP_Error( 'rmdir_fail', 'حذف پوشه ناموفق: ' . $rel );
		}
		return true;
	}

	/**
	 * Recursive directory delete.
	 *
	 * @param string $dir Absolute path.
	 */
	private static function rrmdir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = scandir( $dir );
		if ( ! is_array( $items ) ) {
			return;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_dir( $path ) ) {
				self::rrmdir( $path );
			} else {
				@chmod( $path, 0644 );
				@unlink( $path );
			}
		}
		@chmod( $dir, 0755 );
		@rmdir( $dir );
	}
}
