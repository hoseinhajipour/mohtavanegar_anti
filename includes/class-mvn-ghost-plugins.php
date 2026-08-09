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
		$has_hex_php = false;
		$has_mu_malware = false;
		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( $dir . '/mu-plugins' );
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
			if ( preg_match( '/^\.?[a-f0-9]{6,16}\.php$/i', $entry ) ) {
				$found[]     = 'wp-content/' . $entry;
				$has_hex_php = true;
			} elseif ( preg_match( '/^\.?[a-f0-9]{6,16}\.zip$/i', $entry ) ) {
				$found[] = 'wp-content/' . $entry;
			} elseif ( in_array( $entry, array( '.user.ini', 'user.ini', 'php.ini' ), true ) ) {
				$found[] = 'wp-content/' . $entry;
			}
		}
		// Early drop-ins that reinfect mu-plugins — remove whenever other IoCs exist.
		$db = $dir . '/db.php';
		if ( is_file( $db ) ) {
			$content = (string) @file_get_contents( $db );
			$is_ours = ( false !== strpos( $content, 'MVN Safe DB Bootstrap' ) );
			if ( ! $is_ours && ( $has_hex_php || $has_mu_malware || self::db_php_is_hostile( $content ) ) ) {
				$found[] = 'wp-content/db.php';
			}
		}
		$ac = $dir . '/advanced-cache.php';
		if ( is_file( $ac ) && ( $has_hex_php || $has_mu_malware ) ) {
			$ac_c = (string) @file_get_contents( $ac );
			if ( false === strpos( $ac_c, 'MVN Safe' ) && ( self::db_php_is_hostile( $ac_c ) || $has_mu_malware ) ) {
				$found[] = 'wp-content/advanced-cache.php';
			}
		}
		foreach ( array( ABSPATH . '.user.ini', ABSPATH . 'php.ini' ) as $abs ) {
			if ( is_file( $abs ) ) {
				$c = (string) @file_get_contents( $abs );
				if ( preg_match( '/auto_prepend_file|auto_append_file/i', $c ) ) {
					$found[] = mvn_rel_path( $abs );
				}
			}
		}
		return array_values( array_unique( $found ) );
	}

	/**
	 * Hostile markers for db.php / advanced-cache.php drop-ins.
	 *
	 * @param string $content File contents.
	 */
	private static function db_php_is_hostile( $content ) {
		if ( '' === $content ) {
			return false;
		}
		if ( preg_match( '/\b(?:eval|assert|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content )
			&& preg_match( '/base64_decode|\$_(?:POST|GET|REQUEST|COOKIE)|create_function/i', $content ) ) {
			return true;
		}
		if ( preg_match( '/auto_prepend_file|zonal-runner|xdav|mu-plugins.*file_put_contents|\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}/i', $content ) ) {
			return true;
		}
		if ( substr_count( $content, '\\x' ) > 80 && ! preg_match( '/wpdb|DB_HOST|mysqli_connect|hyperdb|Query Monitor/i', $content ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Force-delete a file: chmod → quarantine → unlink → rename into mvn-data/kill.
	 *
	 * @param string $rel Relative path.
	 * @param string $reason Quarantine reason.
	 * @return true|WP_Error
	 */
	public static function force_delete_file( $rel, $reason = 'malware_persistence' ) {
		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) ) {
			return true;
		}
		@chmod( $abs, 0644 );
		MVN_Quarantine::store( $rel, array( 'reason' => $reason ) );
		if ( @unlink( $abs ) ) {
			return true;
		}
		// Rename aside even if file is open (common for db.php drop-in).
		$kill_root = mvn_data_dir() . '/kill';
		if ( ! is_dir( $kill_root ) ) {
			wp_mkdir_p( $kill_root );
		}
		$dest = $kill_root . '/' . basename( $abs ) . '-' . gmdate( 'YmdHis' ) . '-' . substr( md5( $abs . wp_rand() ), 0, 6 );
		if ( @rename( $abs, $dest ) ) {
			@chmod( $dest, 0644 );
			@unlink( $dest );
			return true;
		}
		$alt = $abs . '.__mvn_dead_' . gmdate( 'YmdHis' );
		if ( @rename( $abs, $alt ) ) {
			@unlink( $alt );
			if ( ! is_file( $abs ) ) {
				return true;
			}
		}
		return new WP_Error(
			'force_unlink_fail',
			'حذف قفل‌شده ناموفق: ' . $rel . ' — از File Manager تیک Trash را بردارید یا با SSH: chattr -i && rm -f'
		);
	}

	/**
	 * Neutralize early drop-ins (db.php / advanced-cache.php) that reinfect before MU loads.
	 *
	 * @return array{deleted:string[],errors:string[],safe_db:string}
	 */
	public static function neutralize_early_dropins() {
		$out = array(
			'deleted' => array(),
			'errors'  => array(),
			'safe_db' => '',
		);
		foreach ( array( 'wp-content/db.php', 'wp-content/advanced-cache.php' ) as $rel ) {
			$abs = mvn_abs_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			$content = (string) @file_get_contents( $abs );
			if ( false !== strpos( $content, 'MVN Safe DB Bootstrap' ) || false !== strpos( $content, 'MVN Safe Cache' ) ) {
				continue;
			}
			// Always remove when called from purge on infected site.
			$ok = self::force_delete_file( $rel, 'early_dropin_neutralize' );
			if ( is_wp_error( $ok ) ) {
				$out['errors'][] = $ok->get_error_message();
			} else {
				$out['deleted'][] = $rel;
			}
		}
		// Optional: install a short-lived safe db.php that cleans then boots core wpdb.
		$need_safe = is_dir( WP_CONTENT_DIR . '/mu-plugins' )
			&& (bool) preg_grep( '/zonal|xdav/i', scandir( WP_CONTENT_DIR . '/mu-plugins' ) ?: array() );
		if ( $need_safe || ! empty( $out['deleted'] ) ) {
			$installed = self::install_safe_db_dropin();
			if ( is_wp_error( $installed ) ) {
				$out['errors'][] = $installed->get_error_message();
			} else {
				$out['safe_db'] = $installed;
			}
		}
		return $out;
	}

	/**
	 * Write a temporary safe db.php that purges reinfection then loads core wpdb.
	 *
	 * @return string|WP_Error Relative path.
	 */
	public static function install_safe_db_dropin() {
		$path   = WP_CONTENT_DIR . '/db.php';
		$expire = time() + ( 2 * DAY_IN_SECONDS );
		$code   = '<?php
/**
 * MVN Safe DB Bootstrap — temporary drop-in. Removes reinfecting malware then uses core wpdb.
 * Auto-removes when clean or after TTL. Safe to delete manually anytime.
 */
if ( ! defined( \'ABSPATH\' ) ) { exit; }
if ( ! defined( \'WP_CONTENT_DIR\' ) ) { return; }
$__mvn_c = WP_CONTENT_DIR;
$__mvn_expire = ' . (int) $expire . ';
$__mvn_still = false;
$__mvn_rm = static function ( $p ) {
	if ( is_file( $p ) ) {
		@chmod( $p, 0644 );
		if ( ! @unlink( $p ) ) { @rename( $p, $p . \'.__mvn_dead\' ); }
	}
};
$__mvn_mu = $__mvn_c . \'/mu-plugins\';
if ( is_dir( $__mvn_mu ) ) {
	foreach ( @scandir( $__mvn_mu ) ?: array() as $__e ) {
		if ( \'.\' === $__e || \'..\' === $__e || 0 === strpos( $__e, \'zz-mvn-kill-\' ) ) { continue; }
		if ( \'index.php\' === $__e ) { continue; }
		if ( preg_match( \'/zonal|xdav|security-helper|wp-[a-z0-9]{6}-loader/i\', $__e ) || preg_match( \'/\\.php$/i\', $__e ) ) {
			$__mvn_rm( $__mvn_mu . \'/\' . $__e );
		}
	}
	foreach ( @scandir( $__mvn_mu ) ?: array() as $__e ) {
		if ( preg_match( \'/zonal|xdav/i\', $__e ) ) { $__mvn_still = true; break; }
	}
}
foreach ( @scandir( $__mvn_c ) ?: array() as $__e ) {
	if ( preg_match( \'/^\\.?[a-f0-9]{6,16}\\.(?:php|zip)$/i\', $__e ) || in_array( $__e, array( \'.user.ini\', \'user.ini\' ), true ) ) {
		$__mvn_rm( $__mvn_c . \'/\' . $__e );
	}
}
foreach ( @scandir( $__mvn_c ) ?: array() as $__e ) {
	if ( preg_match( \'/^\\.?[a-f0-9]{6,16}\\.(?:php|zip)$/i\', $__e ) || \'.user.ini\' === $__e ) {
		$__mvn_still = true;
		break;
	}
}
$__mvn_ac = $__mvn_c . \'/advanced-cache.php\';
if ( is_file( $__mvn_ac ) ) {
	$__raw = (string) @file_get_contents( $__mvn_ac );
	if ( false === strpos( $__raw, \'MVN Safe\' ) && preg_match( \'/eval|base64_decode|gzinflate|zonal|xdav/i\', $__raw ) ) {
		$__mvn_rm( $__mvn_ac );
	}
}
if ( ! isset( $wpdb ) ) {
	require_once ABSPATH . WPINC . \'/class-wpdb.php\';
	$wpdb = new wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
}
if ( ! $__mvn_still || time() > $__mvn_expire ) {
	@unlink( __FILE__ );
}
';
		if ( false === @file_put_contents( $path, $code ) ) {
			return new WP_Error( 'safe_db_write', 'نوشتن db.php امن ناموفق بود.' );
		}
		@chmod( $path, 0644 );
		return 'wp-content/db.php';
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
			$abs = mvn_abs_path( $rel );
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
	 * Purge known malware plugin folders/files and scrub active_plugins + tracker options.
	 *
	 * Scrub DB first, rename folders out of plugins (breaks reload), then delete.
	 * Active malware often restores itself on shutdown if we only unlink while loaded.
	 *
	 * @return array{deleted:string[],renamed:string[],options:string[],usermeta:string[],active_scrubbed:int,errors:string[],kill_mu:string}
	 */
	public static function purge_known() {
		$result = array(
			'deleted'         => array(),
			'renamed'         => array(),
			'options'         => array(),
			'usermeta'        => array(),
			'active_scrubbed' => 0,
			'errors'          => array(),
			'kill_mu'         => '',
		);

		mvn_ensure_data_dirs();

		// 0) Neutralize db.php / advanced-cache.php FIRST — they load before MU and reinfect.
		$early = self::neutralize_early_dropins();
		$result['deleted'] = array_merge( $result['deleted'], $early['deleted'] );
		$result['errors']  = array_merge( $result['errors'], $early['errors'] );
		if ( ! empty( $early['safe_db'] ) ) {
			$result['safe_db'] = $early['safe_db'];
		}

		// 1) Scrub active_plugins.
		$result['active_scrubbed'] = self::scrub_active_plugins();

		// 1b) Kill remaining wp-content root / mu IoCs (.user.ini, hex PHP, zonal MU file).
		foreach ( self::discover_wpcontent_root_iocs() as $rel ) {
			if ( 'wp-content/db.php' === $rel ) {
				continue; // handled / replaced by safe bootstrap
			}
			$ok = self::force_delete_file( $rel, 'wpcontent_root_ioc' );
			if ( is_wp_error( $ok ) ) {
				$result['errors'][] = $ok->get_error_message();
			} else {
				$result['deleted'][] = $rel;
			}
		}

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
			$abs = $dir . '/' . $name;
			$rel = 'wp-content/plugins/' . $name;
			if ( ! is_file( $abs ) ) {
				continue;
			}
			$id = MVN_Quarantine::store( $rel, array( 'reason' => 'known_malware_plugin' ) );
			if ( ! $id ) {
				$result['errors'][] = 'قرنطینه ناموفق: ' . $rel;
				continue;
			}
			if ( @unlink( $abs ) ) {
				$result['deleted'][] = $rel;
			} else {
				$alt = $abs . '.__mvn_dead_' . gmdate( 'YmdHis' );
				if ( @rename( $abs, $alt ) ) {
					@unlink( $alt );
					$result['deleted'][] = $rel . ' (rename)';
				} else {
					$result['errors'][] = 'حذف ناموفق (قفل فایل؟): ' . $rel;
				}
			}
		}

		foreach ( self::persistence_path_globs() as $rel ) {
			$abs = mvn_abs_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			$id = MVN_Quarantine::store( $rel, array( 'reason' => 'malware_persistence_dropper' ) );
			if ( $id && @unlink( $abs ) ) {
				$result['deleted'][] = $rel;
			} elseif ( ! $id ) {
				$result['errors'][] = 'قرنطینه ناموفق: ' . $rel;
			} else {
				$result['errors'][] = 'حذف ناموفق: ' . $rel;
			}
		}

		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
		if ( is_dir( $mu ) ) {
			foreach ( scandir( $mu ) ?: array() as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				if ( 0 === strpos( $entry, 'zz-mvn-kill-' ) ) {
					continue;
				}
				$abs = $mu . '/' . $entry;
				if ( is_dir( $abs ) ) {
					$ok = self::quarantine_and_delete_tree( $abs, 'wp-content/mu-plugins/' . $entry );
					if ( is_wp_error( $ok ) ) {
						$result['errors'][] = $ok->get_error_message();
					} else {
						$result['deleted'][] = 'wp-content/mu-plugins/' . $entry . '/';
					}
					continue;
				}
				if ( ! is_file( $abs ) ) {
					continue;
				}
				// Wipe ALL mu-plugin files on infected sites (except our killer). index.php included if non-empty.
				if ( 'index.php' === $entry ) {
					$c = (string) @file_get_contents( $abs );
					if ( strlen( $c ) < 80 && false === stripos( $c, '<?php' ) ) {
						continue;
					}
					if ( preg_match( '/^\s*<\?php\s*(?:\/\/.*)?\s*(?:silence|Quiet|deny)\b/is', $c ) && strlen( $c ) < 120 ) {
						continue;
					}
				}
				$rel = 'wp-content/mu-plugins/' . $entry;
				$ok  = self::force_delete_file( $rel, 'mu_plugin_wipe' );
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

		if ( function_exists( 'opcache_reset' ) ) {
			@opcache_reset();
		}

		mvn_log(
			'Ghost plugin purge: deleted=' . count( $result['deleted'] )
			. ' renamed=' . count( $result['renamed'] )
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
	 * One-shot MU-plugin that deletes reinfected malware folders early.
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
		$code   = '<?php
/**
 * Plugin Name: MVN One-Shot Malware Killer
 * Description: Auto-generated by Mohtavanegar Antivirus. Deletes reinfectors early each request.
 */
if ( ! defined( \'ABSPATH\' ) ) { exit; }
add_action( \'plugins_loaded\', function () {
	$expire = ' . $ttl . ';
	$slugs  = ' . $export . ';
	$dir    = defined( \'WP_PLUGIN_DIR\' ) ? WP_PLUGIN_DIR : ( WP_CONTENT_DIR . \'/plugins\' );
	$content = WP_CONTENT_DIR;
	$mu = $content . \'/mu-plugins\';
	$still  = false;
	$rm = function ( $path ) {
		if ( is_file( $path ) ) {
			@chmod( $path, 0644 );
			if ( ! @unlink( $path ) ) {
				@rename( $path, $path . \'.__mvn_dead\' );
			}
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
	// Hostile early drop-ins (except our safe bootstrap).
	foreach ( array( \'db.php\', \'advanced-cache.php\' ) as $drop ) {
		$p = $content . \'/\' . $drop;
		if ( ! is_file( $p ) ) { continue; }
		$raw = (string) @file_get_contents( $p );
		if ( false !== strpos( $raw, \'MVN Safe\' ) ) { continue; }
		$rm( $p );
	}
	// MU reinfectors including zonal-runner-tap.php
	if ( is_dir( $mu ) ) {
		foreach ( @scandir( $mu ) ?: array() as $entry ) {
			if ( \'.\' === $entry || \'..\' === $entry || 0 === strpos( $entry, \'zz-mvn-kill-\' ) ) { continue; }
			if ( preg_match( \'/zonal|xdav|security-helper|wp-[a-z0-9]{6}-loader/i\', $entry ) || preg_match( \'/\\.php$/i\', $entry ) ) {
				if ( \'index.php\' === $entry ) { continue; }
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
				$rm( $content . \'/\' . $entry );
			}
		}
		foreach ( @scandir( $content ) ?: array() as $entry ) {
			if ( preg_match( \'/^\\.?[a-f0-9]{6,16}\\.(?:php|zip)$/i\', $entry ) || \'.user.ini\' === $entry ) {
				$still = true;
				break;
			}
		}
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
	if ( time() > $expire || ! $still ) {
		@unlink( __FILE__ );
	}
}, 0 );
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

		$persist = array();
		foreach ( self::persistence_path_globs() as $rel ) {
			if ( is_file( (string) mvn_abs_path( $rel ) ) ) {
				$persist[] = $rel;
			}
		}
		foreach ( self::discover_wpcontent_root_iocs() as $rel ) {
			if ( ! in_array( $rel, $persist, true ) ) {
				$persist[] = $rel;
			}
		}
		$db_safe = WP_CONTENT_DIR . '/db.php';
		if ( is_file( $db_safe ) ) {
			$dbc = (string) @file_get_contents( $db_safe );
			if ( false !== strpos( $dbc, 'MVN Safe DB Bootstrap' ) ) {
				$persist[] = 'wp-content/db.php (db امن موقت MVN — پس از پاک‌سازی خودحذف می‌شود)';
			}
		}
		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( WP_CONTENT_DIR . '/mu-plugins' );
		if ( is_dir( $mu ) ) {
			foreach ( scandir( $mu ) ?: array() as $entry ) {
				if ( 0 === strpos( $entry, 'zz-mvn-kill-' ) ) {
					$persist[] = 'wp-content/mu-plugins/' . $entry . ' (قاتل موقت MVN)';
					continue;
				}
				if ( preg_match( '/^wp-[a-z0-9]{6}-loader\.php$/i', $entry )
					|| 0 === strcasecmp( $entry, '00-site-cache.php' )
					|| preg_match( '/zonal|xdav|security-helper/i', $entry ) ) {
					$persist[] = 'wp-content/mu-plugins/' . $entry;
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
		$like_rows = $wpdb->get_col(
			"SELECT option_name FROM {$wpdb->options}
			WHERE option_name LIKE '%xdav%'
			   OR option_name LIKE '%security_helper%'
			   OR option_name LIKE '%security-helper%'
			   OR option_name LIKE '%zonal%runner%'
			   OR option_name LIKE '%zonal_runner%'
			LIMIT 80"
		);
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
			'persistence'        => $persist,
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
		$extra   = $wpdb->get_col(
			"SELECT option_name FROM {$wpdb->options}
			WHERE option_name LIKE '%xdav%'
			   OR option_name LIKE '%security_helper%'
			   OR option_name LIKE '%security-helper%'
			   OR option_name LIKE '%zonal%runner%'
			   OR option_name LIKE '%zonal_runner%'
			LIMIT 80"
		);
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
