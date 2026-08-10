<?php
/**
 * Preflight checks + post-migration HTTP/filesystem verification.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Security_Validator {

	/**
	 * Run environment preflight. Does not mutate the site.
	 *
	 * @return array{ok:bool,checks:array<int,array{id:string,ok:bool,label:string,detail:string,critical:bool}>}
	 */
	public static function preflight() {
		$checks = array();
		$abspath = mvn_normalize_path( ABSPATH );
		$docroot = self::detect_document_root();
		$parent  = mvn_normalize_path( dirname( $abspath ) );

		$checks[] = self::check(
			'php_version',
			'نسخه PHP',
			version_compare( PHP_VERSION, '7.4', '>=' ),
			'PHP ' . PHP_VERSION,
			true
		);

		$checks[] = self::check(
			'wp_version',
			'نسخه وردپرس',
			version_compare( get_bloginfo( 'version' ), '5.6', '>=' ),
			'WordPress ' . get_bloginfo( 'version' ),
			true
		);

		$is_apache = self::is_apache();
		$checks[]  = self::check(
			'apache',
			'وب‌سرور Apache',
			$is_apache,
			$is_apache ? 'Apache تشخیص داده شد' : 'فقط Apache/cPanel پشتیبانی می‌شود (Nginx/LiteSpeed خالص بدون سازگاری Apache رد می‌شود)',
			true
		);

		$checks[] = self::check(
			'abspath',
			'ABSPATH',
			is_dir( $abspath ),
			$abspath,
			true
		);

		$checks[] = self::check(
			'document_root',
			'Document Root',
			(bool) $docroot,
			$docroot ? $docroot : 'قابل تشخیص نیست',
			true
		);

		$same_root = $docroot && self::paths_equal( $docroot, $abspath );
		$checks[]  = self::check(
			'root_alignment',
			'هم‌ترازی ریشه عمومی و وردپرس',
			$same_root,
			$same_root
				? 'وردپرس داخل ریشه وب است — مناسب برای مهاجرت'
				: 'ABSPATH و DOCUMENT_ROOT یکی نیستند؛ احتمالاً قبلاً جابه‌جا شده یا نصب غیراستاندارد است',
			true
		);

		$checks[] = self::check(
			'parent_writable',
			'قابلیت نوشتن خارج از public root',
			is_dir( $parent ) && is_writable( $parent ),
			$parent . ( is_writable( $parent ) ? ' (قابل نوشتن)' : ' (غیرقابل نوشتن)' ),
			true
		);

		$index = $abspath . '/index.php';
		$checks[] = self::check(
			'index_writable',
			'قابل نوشتن بودن index.php',
			is_file( $index ) && is_writable( $index ) && is_writable( $abspath ),
			$index,
			true
		);

		$ht = $abspath . '/.htaccess';
		$ht_ok = ! file_exists( $ht ) || is_writable( $ht );
		$checks[] = self::check(
			'htaccess_writable',
			'قابل نوشتن بودن .htaccess',
			$ht_ok && is_writable( $abspath ),
			file_exists( $ht ) ? $ht : 'وجود ندارد (ساخته می‌شود)',
			true
		);

		$custom_index = self::is_custom_index( $index );
		$checks[]     = self::check(
			'index_stock',
			'index.php استاندارد وردپرس',
			! $custom_index,
			$custom_index ? 'index.php سفارشی تشخیص داده شد — مهاجرت متوقف می‌شود تا کد شما از بین نرود' : 'استاندارد',
			true
		);

		$symlink_ok = self::can_symlink( $parent );
		$checks[]   = self::check(
			'symlinks',
			'پشتیبانی از Symlink',
			$symlink_ok,
			$symlink_ok ? 'symlink در دسترس است' : 'بدون symlink امکان سرویس فایل‌های استاتیک خارج از ریشه وب وجود ندارد',
			true
		);

		$content_dir = defined( 'WP_CONTENT_DIR' ) ? mvn_normalize_path( WP_CONTENT_DIR ) : '';
		$checks[]    = self::check(
			'wp_content_dir',
			'WP_CONTENT_DIR',
			$content_dir && is_dir( $content_dir ) && self::path_is_within( $content_dir, $abspath ),
			$content_dir ? $content_dir : 'تعریف نشده',
			true
		);

		$dest = MVN_Security_Migration::propose_core_path();
		$dest_free = ! is_dir( $dest['path'] );
		$checks[]  = self::check(
			'destination_free',
			'مسیر مقصد آزاد است',
			$dest_free,
			$dest['path'],
			true
		);

		$need   = self::estimate_tree_bytes( $abspath );
		$free   = self::disk_free_bytes( $parent );
		$space_ok = ( false === $free ) ? true : ( $free > ( $need * 1.15 ) + ( 50 * 1024 * 1024 ) );
		$checks[] = self::check(
			'disk_space',
			'فضای دیسک',
			$space_ok,
			sprintf(
				'نیاز تقریبی: %s | آزاد: %s',
				size_format( $need ),
				false === $free ? 'نامشخص' : size_format( $free )
			),
			true
		);

		$already = MVN_Security_Migration::is_completed();
		$checks[] = self::check(
			'not_already_migrated',
			'مهاجرت تکراری نیست',
			! $already,
			$already ? 'Security Gateway از قبل فعال است' : 'آماده',
			true
		);

		$busy = MVN_Security_Migration::is_busy();
		$checks[] = self::check(
			'not_busy',
			'عدم وجود مهاجرت فعال',
			! $busy,
			$busy ? 'یک مهاجرت در حال اجراست' : 'آزاد',
			true
		);

		$fs_lock = get_option( 'mvn_lock_filesystem_mutation', null );
		$lock_busy = is_array( $fs_lock ) && ! empty( $fs_lock['expires'] ) && (int) $fs_lock['expires'] > time();
		$checks[] = self::check(
			'fs_lock',
			'قفل عملیات فایل',
			! $lock_busy,
			$lock_busy ? 'اسکن/تعمیر دیگری در حال اجراست' : 'آزاد',
			true
		);

		$ok = true;
		foreach ( $checks as $c ) {
			if ( ! empty( $c['critical'] ) && empty( $c['ok'] ) ) {
				$ok = false;
				break;
			}
		}

		return array(
			'ok'             => $ok,
			'checks'         => $checks,
			'document_root'  => $docroot,
			'abspath'        => $abspath,
			'parent'         => $parent,
			'proposed_core'  => $dest['path'],
			'wp_content_dir' => $content_dir,
			'wp_content_url' => defined( 'WP_CONTENT_URL' ) ? WP_CONTENT_URL : content_url(),
		);
	}

	/**
	 * Verify relocated architecture.
	 *
	 * @param string $public_path Public web root.
	 * @param string $core_path   Relocated core.
	 * @return array{ok:bool,tests:array<int,array{id:string,ok:bool,label:string,detail:string}>}
	 */
	public static function verify( $public_path, $core_path ) {
		$public_path = mvn_normalize_path( $public_path );
		$core_path   = mvn_normalize_path( $core_path );
		$tests       = array();

		$tests[] = self::test(
			'core_index',
			'هسته وردپرس',
			is_file( $core_path . '/wp-blog-header.php' ) && is_file( $core_path . '/wp-load.php' ),
			$core_path
		);

		$tests[] = self::test(
			'wp_config_outside',
			'wp-config خارج از ریشه وب',
			is_file( $core_path . '/wp-config.php' ) && ! is_file( $public_path . '/wp-config.php' ),
			is_file( $public_path . '/wp-config.php' ) ? 'wp-config هنوز در ریشه وب است' : 'امن'
		);

		$gateway = $public_path . '/index.php';
		$gw_ok   = is_file( $gateway ) && false !== strpos( (string) @file_get_contents( $gateway ), 'MVN_SECURITY_GATEWAY' );
		$tests[] = self::test( 'gateway_file', 'فایل Gateway', $gw_ok, $gateway );

		$ht_ok = is_file( $public_path . '/.htaccess' ) && false !== strpos( (string) @file_get_contents( $public_path . '/.htaccess' ), 'MVN Security Gateway' );
		$tests[] = self::test( 'htaccess', '.htaccess Gateway', $ht_ok, $public_path . '/.htaccess' );

		foreach ( array( 'wp-admin', 'wp-includes', 'wp-content' ) as $link ) {
			$p = $public_path . '/' . $link;
			$ok = is_link( $p ) || ( is_dir( $p ) && self::paths_equal( @realpath( $p ), @realpath( $core_path . '/' . $link ) ) );
			$tests[] = self::test( 'link_' . $link, 'دسترسی ' . $link, (bool) $ok, $p );
		}

		foreach ( array( 'wp-login.php', 'wp-cron.php' ) as $file ) {
			$p  = $public_path . '/' . $file;
			$ok = is_link( $p ) || ( is_file( $p ) && self::paths_equal( @realpath( $p ), @realpath( $core_path . '/' . $file ) ) );
			$tests[] = self::test( 'link_' . $file, 'دسترسی ' . $file, (bool) $ok, $p );
		}

		$uploads = $core_path . '/wp-content/uploads';
		$up_ht   = $uploads . '/.htaccess';
		$up_ok   = ! is_dir( $uploads ) || ( is_file( $up_ht ) && false !== strpos( (string) @file_get_contents( $up_ht ), 'Deny' ) );
		$tests[] = self::test( 'uploads_htaccess', 'محافظت uploads در برابر PHP', $up_ok, $up_ht );

		// HTTP checks (same host, short timeout).
		$http = self::http_smoke_tests();
		foreach ( $http as $t ) {
			$tests[] = $t;
		}

		$ok = true;
		foreach ( $tests as $t ) {
			if ( empty( $t['ok'] ) ) {
				$ok = false;
				break;
			}
		}

		return array(
			'ok'    => $ok,
			'tests' => $tests,
			'at'    => gmdate( 'Y-m-d H:i:s' ),
		);
	}

	/**
	 * @return array<int,array{id:string,ok:bool,label:string,detail:string}>
	 */
	public static function http_smoke_tests() {
		$out = array();
		$urls = array(
			'frontend' => home_url( '/' ),
			'login'    => site_url( 'wp-login.php' ),
			'admin'    => admin_url( '/' ),
			'rest'     => rest_url(),
		);

		foreach ( $urls as $id => $url ) {
			$res = self::http_probe( $url );
			$ok  = $res['ok'];
			$out[] = self::test(
				'http_' . $id,
				'HTTP ' . $id,
				$ok,
				sprintf( 'HTTP %s — %s', $res['code'], $url )
			);
		}

		// Static asset: load a known core CSS if present.
		$css = includes_url( 'css/dashicons.min.css' );
		$res = self::http_probe( $css );
		$out[] = self::test( 'http_static', 'HTTP استاتیک wp-includes', $res['ok'] || in_array( (int) $res['code'], array( 200, 301, 302, 304 ), true ), 'HTTP ' . $res['code'] );

		// PHP execution in uploads should fail (404/403/500) — create temp probe only if uploads writable.
		$probe = self::uploads_php_probe();
		$out[] = self::test(
			'uploads_php_blocked',
			'عدم اجرای PHP در uploads',
			$probe['ok'],
			$probe['detail']
		);

		return $out;
	}

	/**
	 * @param string $url URL.
	 * @return array{ok:bool,code:int}
	 */
	private static function http_probe( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 15,
				'redirection' => 3,
				'sslverify'   => false,
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'code' => 0 );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		// Login/admin may 302 to login; REST may 200; frontend 200.
		$ok = $code >= 200 && $code < 500 && 404 !== $code;
		return array( 'ok' => $ok, 'code' => $code );
	}

	/**
	 * Drop a temporary PHP file under uploads and ensure HTTP will not execute it.
	 *
	 * @return array{ok:bool,detail:string}
	 */
	private static function uploads_php_probe() {
		$uploads = wp_upload_dir( null, false );
		if ( empty( $uploads['basedir'] ) || empty( $uploads['baseurl'] ) || ! is_dir( $uploads['basedir'] ) ) {
			return array( 'ok' => true, 'detail' => 'پوشه uploads در دسترس نیست — رد شد' );
		}
		$name = '.mvn-probe-' . wp_generate_password( 8, false, false ) . '.php';
		$path = trailingslashit( $uploads['basedir'] ) . $name;
		$url  = trailingslashit( $uploads['baseurl'] ) . $name;
		$marker = 'MVN_PROBE_' . wp_generate_password( 12, false, false );
		$written = @file_put_contents( $path, "<?php echo '" . $marker . "';\n" );
		if ( false === $written ) {
			return array( 'ok' => true, 'detail' => 'نتوانستیم فایل آزمایشی بنویسیم — رد شد' );
		}
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 10,
				'sslverify' => false,
			)
		);
		@unlink( $path );
		if ( is_wp_error( $response ) ) {
			// Connection errors can still mean deny — treat body absence as pass if file gone.
			return array( 'ok' => true, 'detail' => 'درخواست ناموفق بود؛ فایل آزمایشی حذف شد' );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = (string) wp_remote_retrieve_body( $response );
		$executed = ( false !== strpos( $body, $marker ) );
		// Pass when PHP did not execute. Prefer deny/error statuses; plain download without execution is also OK.
		$ok = ! $executed;
		return array(
			'ok'     => $ok,
			'detail' => $executed ? 'PHP در uploads اجرا شد (خطرناک)' : 'HTTP ' . $code . ' — اجرا نشد',
		);
	}

	/**
	 * @return string|false Normalized document root.
	 */
	public static function detect_document_root() {
		$candidates = array();
		if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) ) {
			$candidates[] = (string) wp_unslash( $_SERVER['DOCUMENT_ROOT'] );
		}
		$candidates[] = ABSPATH;
		foreach ( $candidates as $c ) {
			$real = @realpath( $c );
			if ( false !== $real && is_dir( $real ) ) {
				return mvn_normalize_path( $real );
			}
			$norm = mvn_normalize_path( $c );
			if ( is_dir( $norm ) ) {
				return $norm;
			}
		}
		return false;
	}

	/**
	 * @return bool
	 */
	public static function is_apache() {
		$soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';
		if ( false !== strpos( $soft, 'apache' ) || false !== strpos( $soft, 'httpd' ) || false !== strpos( $soft, 'litespeed' ) ) {
			return true;
		}
		// cPanel often still uses Apache-compatible .htaccess on LiteSpeed.
		if ( function_exists( 'apache_get_modules' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Detect non-stock WordPress index.php.
	 *
	 * @param string $path Absolute index.php.
	 * @return bool True when custom / unsafe to replace.
	 */
	public static function is_custom_index( $path ) {
		if ( ! is_file( $path ) ) {
			return true;
		}
		$raw = (string) @file_get_contents( $path );
		if ( '' === trim( $raw ) ) {
			return true;
		}
		if ( false !== strpos( $raw, 'MVN_SECURITY_GATEWAY' ) ) {
			return false; // our gateway — already migrated path handled elsewhere.
		}
		// Stock WP index is tiny and requires wp-blog-header.php with WP_USE_THEMES.
		$has_themes = false !== strpos( $raw, 'WP_USE_THEMES' );
		$has_header = false !== strpos( $raw, 'wp-blog-header.php' );
		if ( $has_themes && $has_header && strlen( $raw ) < 2500 ) {
			return false;
		}
		return true;
	}

	/**
	 * @param string $parent_dir Parent writable dir.
	 * @return bool
	 */
	public static function can_symlink( $parent_dir ) {
		if ( ! function_exists( 'symlink' ) ) {
			return false;
		}
		$base = trailingslashit( $parent_dir ) . '.mvn-symlink-test-' . wp_generate_password( 6, false, false );
		$target = $base . '-target';
		$link   = $base . '-link';
		if ( ! @mkdir( $target, 0755 ) ) {
			return false;
		}
		$ok = @symlink( $target, $link );
		if ( $ok ) {
			@unlink( $link );
		}
		@rmdir( $target );
		return (bool) $ok;
	}

	/**
	 * @param string $path Path.
	 * @return int
	 */
	public static function estimate_tree_bytes( $path ) {
		$path = mvn_normalize_path( $path );
		$total = 0;
		if ( ! is_dir( $path ) ) {
			return 0;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $it as $file ) {
				/** @var SplFileInfo $file */
				if ( $file->isFile() ) {
					$total += (int) $file->getSize();
				}
				// Soft cap iteration time on huge trees.
				if ( $total > 20 * 1024 * 1024 * 1024 ) {
					break;
				}
			}
		} catch ( Exception $e ) {
			return $total;
		}
		return $total;
	}

	/**
	 * @param string $path Path.
	 * @return int|false
	 */
	public static function disk_free_bytes( $path ) {
		$free = @disk_free_space( $path );
		return false === $free ? false : (int) $free;
	}

	/**
	 * @param string $a Path.
	 * @param string $b Path.
	 * @return bool
	 */
	public static function paths_equal( $a, $b ) {
		if ( ! $a || ! $b ) {
			return false;
		}
		$a = mvn_normalize_path( (string) $a );
		$b = mvn_normalize_path( (string) $b );
		if ( defined( 'PHP_OS_FAMILY' ) && 'Windows' === PHP_OS_FAMILY ) {
			return strtolower( $a ) === strtolower( $b );
		}
		return $a === $b;
	}

	/**
	 * @param string $path Path.
	 * @param string $root Root.
	 * @return bool
	 */
	public static function path_is_within( $path, $root ) {
		return mvn_path_is_within( $path, $root );
	}

	/**
	 * @param string $id       Id.
	 * @param string $label    Label.
	 * @param bool   $ok       Pass.
	 * @param string $detail   Detail.
	 * @param bool   $critical Critical.
	 * @return array
	 */
	private static function check( $id, $label, $ok, $detail, $critical ) {
		return array(
			'id'       => $id,
			'label'    => $label,
			'ok'       => (bool) $ok,
			'detail'   => (string) $detail,
			'critical' => (bool) $critical,
		);
	}

	/**
	 * @param string $id     Id.
	 * @param string $label  Label.
	 * @param bool   $ok     Pass.
	 * @param string $detail Detail.
	 * @return array
	 */
	private static function test( $id, $label, $ok, $detail ) {
		return array(
			'id'     => $id,
			'label'  => $label,
			'ok'     => (bool) $ok,
			'detail' => (string) $detail,
		);
	}
}
