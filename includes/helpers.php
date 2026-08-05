<?php
/**
 * Shared helpers: data directory, JSON state, paths, IP, logging.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base data directory (outside plugin, survives plugin updates).
 */
function mvn_data_dir() {
	$dir = WP_CONTENT_DIR . '/mvn-data';
	return apply_filters( 'mvn_data_dir', $dir );
}

function mvn_ensure_data_dirs() {
	$base  = mvn_data_dir();
	$dirs  = array( $base, $base . '/quarantine', $base . '/backups', $base . '/backups/plugins', $base . '/logs', $base . '/state' );
	$ht    = "# BEGIN Mohtavanegar\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n# END Mohtavanegar\n";
	foreach ( $dirs as $dir ) {
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		if ( is_dir( $dir ) && ! file_exists( $dir . '/index.php' ) ) {
			@file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" );
		}
	}
	if ( is_dir( $base ) && ! file_exists( $base . '/.htaccess' ) ) {
		@file_put_contents( $base . '/.htaccess', $ht );
	}
	return $base;
}

/**
 * Read a JSON state file.
 */
function mvn_state_read( $name, $default = array() ) {
	$file = mvn_data_dir() . '/state/' . preg_replace( '/[^a-z0-9_\-]/i', '', $name ) . '.json';
	if ( ! file_exists( $file ) ) {
		return $default;
	}
	$raw  = @file_get_contents( $file );
	$data = json_decode( $raw, true );
	return is_array( $data ) ? $data : $default;
}

/**
 * Write a JSON state file.
 */
function mvn_state_write( $name, $data ) {
	mvn_ensure_data_dirs();
	$file = mvn_data_dir() . '/state/' . preg_replace( '/[^a-z0-9_\-]/i', '', $name ) . '.json';
	return (bool) @file_put_contents( $file, wp_json_encode( $data ) );
}

function mvn_state_delete( $name ) {
	$file = mvn_data_dir() . '/state/' . preg_replace( '/[^a-z0-9_\-]/i', '', $name ) . '.json';
	if ( file_exists( $file ) ) {
		@unlink( $file );
	}
}

/**
 * Absolute path from a site-relative path, guarded against traversal.
 */
function mvn_abs_path( $rel ) {
	$rel  = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
	$base = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
	$path = $base . '/' . $rel;
	// Block directory traversal.
	if ( false !== strpos( $rel, '..' ) ) {
		return false;
	}
	return $path;
}

/**
 * Site-relative path from an absolute path.
 */
function mvn_rel_path( $abs ) {
	$abs  = str_replace( '\\', '/', $abs );
	$base = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/';
	if ( 0 === strpos( $abs, $base ) ) {
		return substr( $abs, strlen( $base ) );
	}
	return $abs;
}

/**
 * Real client IP (REMOTE_ADDR only - headers are spoofable).
 */
function mvn_get_ip() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
	return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
}

/**
 * Append a line to the plugin log.
 */
function mvn_log( $message ) {
	$dir = mvn_data_dir() . '/logs';
	if ( ! is_dir( $dir ) ) {
		mvn_ensure_data_dirs();
	}
	$line = '[' . gmdate( 'Y-m-d H:i:s' ) . '] ' . $message . "\n";
	@file_put_contents( $dir . '/activity.log', $line, FILE_APPEND | LOCK_EX );
}

/**
 * Folder names of this antivirus plugin (never scan/fix our own files).
 */
function mvn_self_plugin_slugs() {
	$slugs = array(
		'mohtavanegar-antivirus',
		'mohtavanegar_anti',
		'mohtavanegar-anti',
	);
	if ( defined( 'MVN_PLUGIN_FILE' ) ) {
		$slugs[] = basename( dirname( MVN_PLUGIN_FILE ) );
	}
	return array_unique( apply_filters( 'mvn_self_plugin_slugs', $slugs ) );
}

function mvn_is_self_plugin_path( $rel ) {
	$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
	foreach ( mvn_self_plugin_slugs() as $slug ) {
		$base = 'wp-content/plugins/' . $slug;
		if ( $rel === $base || 0 === strpos( $rel, $base . '/' ) ) {
			return true;
		}
	}
	return false;
}

/**
 * WordPress core file paths (repaired from bundled zip — not signature-scanned).
 */
function mvn_core_root_files() {
	return array(
		'index.php',
		'wp-load.php',
		'wp-settings.php',
		'wp-blog-header.php',
		'wp-cron.php',
		'wp-login.php',
		'wp-signup.php',
		'wp-trackback.php',
		'wp-comments-post.php',
		'wp-mail.php',
		'wp-activate.php',
		'xmlrpc.php',
		'wp-links-opml.php',
	);
}

function mvn_is_core_path( $rel ) {
	$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
	if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
		return true;
	}
	return in_array( $rel, mvn_core_root_files(), true );
}

/**
 * Should this file be excluded from malware signature scanning?
 */
function mvn_is_skippable_scan_file( $rel ) {
	$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
	if ( mvn_is_core_path( $rel ) ) {
		return true;
	}
	if ( mvn_is_self_plugin_path( $rel ) ) {
		return true;
	}
	if ( mvn_is_skippable_dir( dirname( $rel ) ) ) {
		return true;
	}
	// Composer / npm dependencies — high false-positive rate; repair plugins from repo instead.
	if ( preg_match( '#/(vendor|node_modules)/#', $rel ) ) {
		return true;
	}
	// Wordfence runtime data (rules cache, config blobs).
	if ( 0 === strpos( $rel, 'wp-content/wflogs/' ) ) {
		return true;
	}
	return (bool) apply_filters( 'mvn_skip_scan_file', false, $rel );
}

/**
 * Is this path inside a directory the scanner should skip?
 */
function mvn_is_skippable_dir( $rel ) {
	$rel = trim( str_replace( '\\', '/', $rel ), '/' );
	$skip = array(
		'wp-content/mvn-data',
		'wp-content/cache',
		'wp-content/upgrade',
		'wp-content/uploads/cache',
		'wp-content/wflogs',
	);
	foreach ( mvn_self_plugin_slugs() as $slug ) {
		$skip[] = 'wp-content/plugins/' . $slug;
	}
	foreach ( $skip as $s ) {
		if ( $rel === $s || 0 === strpos( $rel, $s . '/' ) ) {
			return true;
		}
		if ( false !== strpos( $rel, '/.git' ) || false !== strpos( $rel, '/node_modules' ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Extensions the scanner treats as code / injectable content.
 */
function mvn_scannable_extensions() {
	return array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'pht', 'inc', 'module', 'js', 'html', 'htm', 'svg', 'txt', 'htaccess' );
}

/**
 * Binary/archive extensions never scanned.
 */
function mvn_binary_extensions() {
	return array( 'zip', 'gz', 'tar', 'rar', '7z', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'mp4', 'mp3', 'avi', 'mov', 'pdf', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'exe', 'dll', 'so', 'psd', 'ai', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'sql' );
}

/**
 * Human readable file size.
 */
function mvn_size_format( $bytes ) {
	$bytes = (float) $bytes;
	if ( $bytes >= 1048576 ) {
		return round( $bytes / 1048576, 1 ) . ' MB';
	}
	if ( $bytes >= 1024 ) {
		return round( $bytes / 1024, 1 ) . ' KB';
	}
	return $bytes . ' B';
}

/**
 * Dashboard security checklist (done / pending items with links).
 *
 * @param array $ctx Optional preloaded context keys: last, issues, ht, core, hard, integrity, perms.
 * @return array{items:array,done:int,total:int,pct:int}
 */
function mvn_security_checklist( $ctx = array() ) {
	$last      = isset( $ctx['last'] ) ? $ctx['last'] : get_option( MVN_OPTION_LASTSCAN, array() );
	$issues    = isset( $ctx['issues'] ) ? $ctx['issues'] : ( class_exists( 'MVN_Scanner' ) ? MVN_Scanner::get_issues() : array() );
	$ht        = isset( $ctx['ht'] ) ? $ctx['ht'] : ( class_exists( 'MVN_Htaccess_Guard' ) ? MVN_Htaccess_Guard::root_status() : array() );
	$core      = isset( $ctx['core'] ) ? $ctx['core'] : ( class_exists( 'MVN_Core_Repair' ) ? MVN_Core_Repair::source_status() : array() );
	$hard      = isset( $ctx['hard'] ) ? $ctx['hard'] : ( class_exists( 'MVN_Hardening' ) ? MVN_Hardening::instance()->settings() : array() );
	$integrity = isset( $ctx['integrity'] ) ? $ctx['integrity'] : ( class_exists( 'MVN_Core_Integrity' ) ? MVN_Core_Integrity::last_summary() : array() );
	$perms     = isset( $ctx['perms'] ) ? $ctx['perms'] : ( class_exists( 'MVN_Permissions' ) ? MVN_Permissions::get_state() : array() );

	$issue_count = is_array( $issues ) ? count( $issues ) : 0;
	$crit        = 0;
	if ( is_array( $issues ) ) {
		foreach ( $issues as $iss ) {
			if ( isset( $iss['severity'] ) && 'critical' === $iss['severity'] ) {
				$crit++;
			}
		}
	}

	$scanned = ! empty( $last['finished_at'] ) || ! empty( $last['id'] );
	$ht_ok   = ! empty( $ht['matches'] );
	$zip_ok  = ! empty( $core['zip_ok'] );
	$integ_ok = ! empty( $integrity['finished_at'] ) && ! empty( $integrity['ok'] );
	$integ_ran = ! empty( $integrity['finished_at'] );
	$perms_ok = ! empty( $perms['status'] ) && 'done' === $perms['status'];
	$https_ok = ( is_ssl() || ( 0 === strpos( (string) home_url(), 'https://' ) ) );
	$debug_ok = ! ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) );

	$items = array(
		array(
			'id'     => 'scan',
			'title'  => 'اسکن امنیتی سایت',
			'desc'   => $scanned ? 'آخرین اسکن انجام شده' : 'هنوز اسکنی ثبت نشده',
			'done'   => $scanned,
			'url'    => admin_url( 'admin.php?page=mvn-scan' ),
			'action' => 'شروع اسکن',
		),
		array(
			'id'     => 'fix_issues',
			'title'  => 'رفع یافته‌های باز',
			'desc'   => $issue_count > 0
				? sprintf( '%d مورد باز%s', $issue_count, $crit > 0 ? ' (' . $crit . ' بحرانی)' : '' )
				: ( $scanned ? 'مورد بازی باقی نمانده' : 'پس از اسکن بررسی شود' ),
			'done'   => $scanned && 0 === $issue_count,
			'url'    => admin_url( 'admin.php?page=mvn-fix' ),
			'action' => 'رفع مشکلات',
		),
		array(
			'id'     => 'core_integrity',
			'title'  => 'یکپارچگی هسته وردپرس',
			'desc'   => ! $integ_ran
				? 'checksum هسته هنوز اجرا نشده'
				: ( $integ_ok ? 'هسته سالم است' : 'تغییر/حذف در فایل‌های هسته یافت شد' ),
			'done'   => $integ_ok,
			'url'    => admin_url( 'admin.php?page=mvn-repair' ),
			'action' => 'بررسی هسته',
		),
		array(
			'id'     => 'core_zip',
			'title'  => 'منبع تعمیر هسته (zip)',
			'desc'   => $zip_ok ? 'wordpress_core.zip آماده است' : 'فایل zip سالم در دسترس نیست',
			'done'   => $zip_ok,
			'url'    => admin_url( 'admin.php?page=mvn-repair' ),
			'action' => 'صفحه تعمیر',
		),
		array(
			'id'     => 'htaccess',
			'title'  => 'htaccess ریشه امن',
			'desc'   => $ht_ok
				? 'مطابق پیش‌فرض پلاگین'
				: ( empty( $ht['exists'] ) ? 'فایل وجود ندارد' : 'با پیش‌فرض متفاوت است' ),
			'done'   => $ht_ok,
			'url'    => admin_url( 'admin.php?page=mvn-repair' ),
			'action' => 'بازیابی htaccess',
		),
		array(
			'id'     => 'permissions',
			'title'  => 'اصلاح سطح دسترسی فایل‌ها',
			'desc'   => $perms_ok ? 'آخرین اجرای اصلاح دسترسی انجام شده' : 'هنوز اجرا نشده یا ناتمام است',
			'done'   => $perms_ok,
			'url'    => admin_url( 'admin.php?page=mvn-repair' ),
			'action' => 'اصلاح دسترسی',
		),
		array(
			'id'     => 'xmlrpc',
			'title'  => 'مسدودسازی XML-RPC',
			'desc'   => ! empty( $hard['block_xmlrpc'] ) ? 'فعال' : 'غیرفعال — خطر brute-force / pingback',
			'done'   => ! empty( $hard['block_xmlrpc'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'brute_force',
			'title'  => 'محافظت Brute Force ورود',
			'desc'   => ! empty( $hard['login_brute_force'] ) ? 'فعال' : 'غیرفعال',
			'done'   => ! empty( $hard['login_brute_force'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'file_edit',
			'title'  => 'غیرفعال‌سازی ویرایشگر فایل',
			'desc'   => ! empty( $hard['disable_file_edit'] ) ? 'DISALLOW_FILE_EDIT فعال' : 'ویرایشگر پوسته/افزونه باز است',
			'done'   => ! empty( $hard['disable_file_edit'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'user_enum',
			'title'  => 'جلوگیری از User Enumeration',
			'desc'   => ! empty( $hard['block_user_enum'] ) ? 'فعال' : 'غیرفعال',
			'done'   => ! empty( $hard['block_user_enum'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'hide_version',
			'title'  => 'مخفی‌سازی نسخه وردپرس',
			'desc'   => ! empty( $hard['hide_wp_version'] ) ? 'فعال' : 'نسخه در خروجی افشا می‌شود',
			'done'   => ! empty( $hard['hide_wp_version'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'headers',
			'title'  => 'هدرهای امنیتی HTTP',
			'desc'   => ! empty( $hard['secure_headers'] ) ? 'فعال' : 'غیرفعال',
			'done'   => ! empty( $hard['secure_headers'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'disable_comments',
			'title'  => 'عدم درج نظرات در کل سایت',
			'desc'   => ! empty( $hard['disable_comments'] ) ? 'نظرات در کل سایت بسته است' : 'نظرات هنوز باز است (اختیاری)',
			'done'   => ! empty( $hard['disable_comments'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'block_external_http',
			'title'  => 'مسدودسازی HTTP خارجی',
			'desc'   => ! empty( $hard['block_external_http'] ) || ( defined( 'WP_HTTP_BLOCK_EXTERNAL' ) && WP_HTTP_BLOCK_EXTERNAL )
				? 'WP_HTTP_BLOCK_EXTERNAL فعال است'
				: 'درخواست‌های خارجی هنوز مجازند (اختیاری)',
			'done'   => ! empty( $hard['block_external_http'] ) || ( defined( 'WP_HTTP_BLOCK_EXTERNAL' ) && WP_HTTP_BLOCK_EXTERNAL ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'block_privileged_signup',
			'title'  => 'عدم ثبت‌نام مدیر / نویسنده',
			'desc'   => ! empty( $hard['block_privileged_signup'] )
				? 'ایجاد کاربر جدید با نقش مدیر/نویسنده مسدود است'
				: 'هنوز می‌توان کاربر جدید مدیر یا نویسنده ساخت (اختیاری)',
			'done'   => ! empty( $hard['block_privileged_signup'] ),
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'سخت‌سازی',
		),
		array(
			'id'     => 'https',
			'title'  => 'HTTPS روی سایت',
			'desc'   => $https_ok ? 'آدرس سایت روی HTTPS است' : 'سایت روی HTTP است — رمزنگاری نیست',
			'done'   => $https_ok,
			'url'    => admin_url( 'options-general.php' ),
			'action' => 'تنظیمات عمومی',
		),
		array(
			'id'     => 'debug',
			'title'  => 'خاموش بودن نمایش Debug',
			'desc'   => $debug_ok ? 'نمایش خطای Debug در فرانت فعال نیست' : 'WP_DEBUG با نمایش خطا روشن است',
			'done'   => $debug_ok,
			'url'    => admin_url( 'admin.php?page=mvn-hardening' ),
			'action' => 'بررسی',
		),
	);

	$done = 0;
	foreach ( $items as $item ) {
		if ( ! empty( $item['done'] ) ) {
			$done++;
		}
	}
	$total = count( $items );

	return array(
		'items' => $items,
		'done'  => $done,
		'total' => $total,
		'pct'   => $total ? (int) round( ( $done / $total ) * 100 ) : 0,
	);
}

/**
 * List files under a directory; paths are relative to $root_abs (not ABSPATH).
 *
 * @param string $root_abs Absolute directory.
 * @param int    $max      Max files.
 * @return string[]
 */
function mvn_list_files_in( $root_abs, $max = 200000 ) {
	$out      = array();
	$root_abs = rtrim( str_replace( '\\', '/', $root_abs ), '/' );
	if ( ! is_dir( $root_abs ) ) {
		return $out;
	}
	$stack = array( $root_abs );
	while ( ! empty( $stack ) && count( $out ) < $max ) {
		$dir   = array_pop( $stack );
		$items = @scandir( $dir );
		if ( false === $items ) {
			continue;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_link( $path ) ) {
				continue;
			}
			if ( is_dir( $path ) ) {
				$stack[] = $path;
			} else {
				$out[] = ltrim( substr( str_replace( '\\', '/', $path ), strlen( $root_abs ) ), '/' );
				if ( count( $out ) >= $max ) {
					break;
				}
			}
		}
	}
	sort( $out );
	return $out;
}

/**
 * Recursive directory listing (files only), site-relative, with skip rules.
 *
 * @param string $root_abs Absolute start directory.
 * @param int    $max      Safety cap on number of files.
 * @return string[] Relative file paths.
 */
function mvn_list_files( $root_abs, $max = 200000 ) {
	$out      = array();
	$root_abs = rtrim( str_replace( '\\', '/', $root_abs ), '/' );
	if ( ! is_dir( $root_abs ) ) {
		return $out;
	}
	$stack = array( $root_abs );
	while ( ! empty( $stack ) && count( $out ) < $max ) {
		$dir = array_pop( $stack );
		$items = @scandir( $dir );
		if ( false === $items ) {
			continue;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_link( $path ) ) {
				continue;
			}
			if ( is_dir( $path ) ) {
				if ( ! mvn_is_skippable_dir( mvn_rel_path( $path ) ) ) {
					$stack[] = $path;
				}
			} else {
				$out[] = mvn_rel_path( $path );
				if ( count( $out ) >= $max ) {
					break;
				}
			}
		}
	}
	sort( $out );
	return $out;
}
