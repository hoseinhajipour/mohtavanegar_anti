<?php
/**
 * Cloak WordPress fingerprints: custom login/admin URLs, remove readme/license,
 * and hide common discovery paths from bots.
 *
 * Always-on (front-end safe). Does not rename physical directories — uses
 * rewrites + URL filters so themes/plugins keep working.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Cloak {

	const OPTION = 'mvn_cloak';

	/** @var MVN_Cloak|null */
	private static $instance = null;

	/** @var bool */
	private $doing_login = false;

	/** @var bool */
	private $filters_on = false;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function defaults() {
		return array(
			'enabled'                 => 0,
			'login_slug'              => 'mvn-access',
			'admin_slug'              => '',
			'hide_wp_admin'           => 1,
			'remove_meta_files'       => 1,
			'block_fingerprint_files' => 1,
			'disable_emoji'           => 1,
			'strip_meta_generator'    => 1,
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public function settings() {
		$saved = get_option( self::OPTION, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return array_merge( self::defaults(), $saved );
	}

	/**
	 * @param array<string,mixed> $input Raw input.
	 * @return array<string,mixed>
	 */
	public function save( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}
		$out = self::defaults();

		$out['enabled']                 = empty( $input['enabled'] ) ? 0 : 1;
		$out['hide_wp_admin']           = empty( $input['hide_wp_admin'] ) ? 0 : 1;
		$out['remove_meta_files']       = empty( $input['remove_meta_files'] ) ? 0 : 1;
		$out['block_fingerprint_files'] = empty( $input['block_fingerprint_files'] ) ? 0 : 1;
		$out['disable_emoji']           = empty( $input['disable_emoji'] ) ? 0 : 1;
		$out['strip_meta_generator']    = empty( $input['strip_meta_generator'] ) ? 0 : 1;

		$login = isset( $input['login_slug'] ) ? self::sanitize_slug( (string) $input['login_slug'] ) : $out['login_slug'];
		if ( '' === $login ) {
			$login = 'mvn-access';
		}
		$out['login_slug'] = $login;

		$admin = isset( $input['admin_slug'] ) ? self::sanitize_slug( (string) $input['admin_slug'] ) : '';
		if ( $admin && ( $admin === $login || self::is_reserved_slug( $admin ) ) ) {
			$admin = '';
		}
		$out['admin_slug'] = $admin;

		if ( self::is_reserved_slug( $out['login_slug'] ) ) {
			$out['login_slug'] = 'mvn-access';
		}

		update_option( self::OPTION, $out, false );

		if ( ! empty( $out['enabled'] ) && ! empty( $out['remove_meta_files'] ) ) {
			self::purge_fingerprint_files();
		}

		self::sync_htaccess_rules( $out );

		flush_rewrite_rules( false );

		mvn_log(
			sprintf(
				'Cloak saved: enabled=%d login=%s admin=%s',
				(int) $out['enabled'],
				$out['login_slug'],
				$out['admin_slug'] ? $out['admin_slug'] : '(off)'
			)
		);

		return $out;
	}

	public function boot() {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			// Still purge files if that flag was left on from a previous enable? Only when enabled.
			return;
		}

		// Custom login must run after WP is loaded, before template output.
		add_action( 'wp_loaded', array( $this, 'maybe_bootstrap_custom_login' ), 1 );
		add_action( 'wp_loaded', array( $this, 'block_default_login' ), 2 );
		add_action( 'init', array( $this, 'add_rewrite_rules' ), 5 );

		add_filter( 'login_url', array( $this, 'filter_login_url' ), 10, 3 );
		add_filter( 'logout_url', array( $this, 'filter_logout_url' ), 10, 2 );
		add_filter( 'lostpassword_url', array( $this, 'filter_login_action_url' ), 10, 2 );
		add_filter( 'register_url', array( $this, 'filter_register_url' ) );
		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( $this, 'filter_wp_redirect' ), 10, 2 );

		if ( ! empty( $s['hide_wp_admin'] ) || ! empty( $s['admin_slug'] ) ) {
			add_action( 'init', array( $this, 'guard_wp_admin' ), 0 );
		}

		if ( ! empty( $s['admin_slug'] ) ) {
			add_filter( 'admin_url', array( $this, 'filter_admin_url' ), 10, 3 );
			add_filter( 'network_admin_url', array( $this, 'filter_network_admin_url' ), 10, 2 );
			add_action( 'plugins_loaded', array( $this, 'maybe_rewrite_admin_request' ), 0 );
		}

		if ( ! empty( $s['block_fingerprint_files'] ) ) {
			add_action( 'init', array( $this, 'block_fingerprint_requests' ), 0 );
		}

		if ( ! empty( $s['remove_meta_files'] ) ) {
			add_action( 'admin_init', array( __CLASS__, 'purge_fingerprint_files' ), 20 );
			add_action( 'upgrader_process_complete', array( __CLASS__, 'purge_fingerprint_files' ), 20 );
		}

		if ( ! empty( $s['disable_emoji'] ) ) {
			add_action( 'init', array( $this, 'disable_emojis' ), 20 );
		}

		if ( ! empty( $s['strip_meta_generator'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_action( 'init', array( $this, 'remove_header_noise' ), 20 );
		}

		// Show custom login URL once in admin notices for the configuring user.
		add_action( 'admin_notices', array( $this, 'admin_notice_urls' ) );
	}

	/**
	 * @param string $slug Raw slug.
	 * @return string
	 */
	public static function sanitize_slug( $slug ) {
		$slug = strtolower( trim( (string) $slug ) );
		$slug = preg_replace( '#[^a-z0-9\-_]+#', '-', $slug );
		$slug = trim( (string) $slug, '-_/' );
		$slug = substr( $slug, 0, 40 );
		return (string) $slug;
	}

	/**
	 * Slugs that must never be used (would break the site).
	 *
	 * @param string $slug Slug.
	 * @return bool
	 */
	public static function is_reserved_slug( $slug ) {
		$slug = strtolower( (string) $slug );
		$reserved = array(
			'admin', 'login', 'wp-admin', 'wp-login', 'wp-login.php', 'wp-content',
			'wp-includes', 'wp-json', 'xmlrpc.php', 'feed', 'comments', 'category',
			'tag', 'author', 'page', 'attachment', 'embed', 'rest', 'favicon.ico',
			'robots.txt', 'sitemap', 'cart', 'checkout', 'my-account', 'shop',
		);
		return in_array( $slug, $reserved, true );
	}

	/**
	 * Delete well-known WordPress discovery files from ABSPATH.
	 *
	 * @return array{removed:string[],skipped:string[]}
	 */
	public static function purge_fingerprint_files() {
		$files = array(
			'readme.html',
			'license.txt',
			'licens.txt',
			'wp-config-sample.php',
		);
		/**
		 * Filter fingerprint files removed from the WordPress root.
		 *
		 * @param string[] $files Relative file names under ABSPATH.
		 */
		$files = apply_filters( 'mvn_cloak_fingerprint_files', $files );
		$out   = array(
			'removed' => array(),
			'skipped' => array(),
		);
		$root = trailingslashit( ABSPATH );
		foreach ( $files as $rel ) {
			$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
			if ( '' === $rel || false !== strpos( $rel, '..' ) || false !== strpos( $rel, '/' ) ) {
				$out['skipped'][] = $rel;
				continue;
			}
			$path = $root . $rel;
			if ( ! is_file( $path ) ) {
				$out['skipped'][] = $rel;
				continue;
			}
			if ( @unlink( $path ) ) {
				$out['removed'][] = $rel;
			} else {
				$out['skipped'][] = $rel;
			}
		}
		return $out;
	}

	/**
	 * Public URLs for the admin UI.
	 *
	 * @return array{login_url:string,admin_url:string,enabled:bool}
	 */
	public function public_urls() {
		$s = $this->settings();
		$login = home_url( '/' . rawurlencode( $s['login_slug'] ) . '/' );
		$admin = ! empty( $s['admin_slug'] )
			? home_url( '/' . rawurlencode( $s['admin_slug'] ) . '/' )
			: admin_url();
		return array(
			'enabled'    => ! empty( $s['enabled'] ),
			'login_url'  => $login,
			'admin_url'  => $admin,
			'login_slug' => $s['login_slug'],
			'admin_slug' => $s['admin_slug'],
		);
	}

	/* ===================== Login cloak ===================== */

	public function add_rewrite_rules() {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || empty( $s['login_slug'] ) ) {
			return;
		}
		$slug = $s['login_slug'];
		add_rewrite_rule( '^' . preg_quote( $slug, '#' ) . '/?$', 'wp-login.php', 'top' );
		add_rewrite_rule( '^' . preg_quote( $slug, '#' ) . '/(.+)/?$', 'wp-login.php?$matches[1]', 'top' );
	}

	/**
	 * Serve wp-login.php under the custom slug without exposing the real filename.
	 */
	public function maybe_bootstrap_custom_login() {
		if ( self::is_cli_or_cron() ) {
			return;
		}
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || empty( $s['login_slug'] ) ) {
			return;
		}
		if ( ! $this->request_is_login_slug( $s['login_slug'] ) ) {
			return;
		}

		$this->doing_login = true;

		// Make WordPress treat this as a login request.
		$GLOBALS['pagenow'] = 'wp-login.php';
		$_SERVER['PHP_SELF'] = '/wp-login.php';

		// Preserve action query args already in the request.
		require ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Return 404 for direct /wp-login.php hits (bots).
	 */
	public function block_default_login() {
		if ( $this->doing_login || self::is_cli_or_cron() ) {
			return;
		}
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		if ( $this->request_targets_wp_login() ) {
			$this->deny_404();
		}
	}

	/**
	 * @param string $url     Login URL.
	 * @param string $redirect Redirect.
	 * @param bool   $force_reauth Force.
	 * @return string
	 */
	public function filter_login_url( $url, $redirect = '', $force_reauth = false ) {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			return $url;
		}
		$login = home_url( '/' . rawurlencode( $s['login_slug'] ) . '/', 'login' );
		if ( ! empty( $redirect ) ) {
			$login = add_query_arg( 'redirect_to', urlencode( $redirect ), $login );
		}
		if ( $force_reauth ) {
			$login = add_query_arg( 'reauth', '1', $login );
		}
		return $login;
	}

	/**
	 * @param string $url URL.
	 * @param string $redirect Redirect.
	 * @return string
	 */
	public function filter_logout_url( $url, $redirect = '' ) {
		unset( $redirect );
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || ! is_string( $url ) ) {
			return $url;
		}
		return str_replace( 'wp-login.php', rawurlencode( $s['login_slug'] ) . '/', $url );
	}

	/**
	 * @param string $url URL.
	 * @param string $redirect Redirect.
	 * @return string
	 */
	public function filter_login_action_url( $url, $redirect = '' ) {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			return $url;
		}
		$base = $this->filter_login_url( '' );
		$out  = add_query_arg( 'action', 'lostpassword', $base );
		if ( ! empty( $redirect ) ) {
			$out = add_query_arg( 'redirect_to', urlencode( $redirect ), $out );
		}
		return $out;
	}

	/**
	 * @param string $url URL.
	 * @return string
	 */
	public function filter_register_url( $url ) {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			return $url;
		}
		return add_query_arg( 'action', 'register', $this->filter_login_url( '' ) );
	}

	/**
	 * Replace wp-login.php in site_url() constructions.
	 *
	 * @param string      $url URL.
	 * @param string      $path Path.
	 * @param string|null $scheme Scheme.
	 * @param int|null    $blog_id Blog id.
	 * @return string
	 */
	public function filter_site_url( $url, $path = '', $scheme = null, $blog_id = null ) {
		unset( $scheme, $blog_id );
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || $this->doing_login ) {
			return $url;
		}
		if ( is_string( $path ) && false !== strpos( $path, 'wp-login.php' ) ) {
			$query = '';
			if ( false !== strpos( $path, '?' ) ) {
				$parts = explode( '?', $path, 2 );
				$query = $parts[1];
			}
			$base = home_url( '/' . rawurlencode( $s['login_slug'] ) . '/' );
			return $query ? ( $base . '?' . $query ) : $base;
		}
		if ( is_string( $url ) && false !== strpos( $url, 'wp-login.php' ) ) {
			return str_replace( 'wp-login.php', rawurlencode( $s['login_slug'] ) . '/', $url );
		}
		return $url;
	}

	/**
	 * @param string $location Location.
	 * @param int    $status Status.
	 * @return string
	 */
	public function filter_wp_redirect( $location, $status = 302 ) {
		unset( $status );
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || ! is_string( $location ) ) {
			return $location;
		}
		if ( false !== strpos( $location, 'wp-login.php' ) ) {
			$location = str_replace( 'wp-login.php', rawurlencode( $s['login_slug'] ) . '/', $location );
		}
		return $location;
	}

	/* ===================== Admin cloak ===================== */

	/**
	 * Map /{admin_slug}/… to /wp-admin/… early via REQUEST_URI rewrite.
	 */
	public function maybe_rewrite_admin_request() {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || empty( $s['admin_slug'] ) || self::is_cli_or_cron() ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$home_path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$home_path = untrailingslashit( $home_path );
		if ( $home_path && 0 === strpos( $path, $home_path ) ) {
			$path = substr( $path, strlen( $home_path ) );
		}
		$path = '/' . ltrim( $path, '/' );
		$slug = '/' . $s['admin_slug'];
		if ( $path !== $slug && 0 !== strpos( $path, $slug . '/' ) ) {
			return;
		}
		$rest = substr( $path, strlen( $slug ) );
		if ( '' === $rest || '/' === $rest ) {
			$rest = '/';
		}
		$new_path = rtrim( $home_path, '/' ) . '/wp-admin' . $rest;
		$query    = (string) wp_parse_url( $uri, PHP_URL_QUERY );
		$_SERVER['REQUEST_URI'] = $new_path . ( $query ? ( '?' . $query ) : '' );
	}

	/**
	 * @param string   $url URL.
	 * @param string   $path Path.
	 * @param int|null $blog_id Blog.
	 * @return string
	 */
	public function filter_admin_url( $url, $path = '', $blog_id = null ) {
		unset( $path, $blog_id );
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || empty( $s['admin_slug'] ) ) {
			return $url;
		}
		return str_replace( '/wp-admin', '/' . rawurlencode( $s['admin_slug'] ), $url );
	}

	/**
	 * @param string $url URL.
	 * @param string $path Path.
	 * @return string
	 */
	public function filter_network_admin_url( $url, $path = '' ) {
		return $this->filter_admin_url( $url, $path, null );
	}

	/**
	 * Hide /wp-admin from guests (404). Optionally redirect logged-in users to custom slug.
	 */
	public function guard_wp_admin() {
		if ( self::is_cli_or_cron() || $this->doing_login ) {
			return;
		}
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		if ( ! $this->request_targets_wp_admin() ) {
			return;
		}

		// Front-end AJAX / form handlers must remain reachable.
		if ( $this->is_admin_ajax_or_post() ) {
			return;
		}

		if ( ! is_user_logged_in() ) {
			if ( ! empty( $s['hide_wp_admin'] ) || ! empty( $s['admin_slug'] ) ) {
				$this->deny_404();
			}
			return;
		}

		// Logged-in users hitting legacy /wp-admin when a custom slug exists → redirect.
		if ( ! empty( $s['admin_slug'] ) && ! $this->request_uses_admin_slug( $s['admin_slug'] ) ) {
			$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/wp-admin/';
			$dest  = preg_replace( '#/wp-admin#', '/' . rawurlencode( $s['admin_slug'] ), $uri, 1 );
			if ( is_string( $dest ) && $dest !== $uri ) {
				wp_safe_redirect( home_url( $dest ), 302 );
				exit;
			}
		}
	}

	/* ===================== Fingerprint noise ===================== */

	public function block_fingerprint_requests() {
		if ( self::is_cli_or_cron() ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? strtolower( (string) wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		if ( preg_match( '#/(readme\.html|license\.txt|licens\.txt|wp-config-sample\.php)(/|$)#', $path ) ) {
			$this->deny_404();
		}
	}

	public function disable_emojis() {
		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_action( 'admin_print_styles', 'print_emoji_styles' );
		remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
		remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
		remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );
		add_filter( 'tiny_mce_plugins', array( $this, 'disable_emojis_tinymce' ) );
		add_filter( 'wp_resource_hints', array( $this, 'disable_emoji_dns' ), 10, 2 );
	}

	/**
	 * @param array $plugins Plugins.
	 * @return array
	 */
	public function disable_emojis_tinymce( $plugins ) {
		if ( is_array( $plugins ) ) {
			return array_diff( $plugins, array( 'wpemoji' ) );
		}
		return array();
	}

	/**
	 * @param array  $urls URLs.
	 * @param string $relation Relation.
	 * @return array
	 */
	public function disable_emoji_dns( $urls, $relation ) {
		if ( 'dns-prefetch' === $relation ) {
			$urls = array_filter(
				(array) $urls,
				static function ( $url ) {
					return is_string( $url ) && false === strpos( $url, 'https://s.w.org/images/core/emoji' );
				}
			);
		}
		return $urls;
	}

	public function remove_header_noise() {
		remove_action( 'wp_head', 'wp_generator' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wp_shortlink_wp_head' );
		// Hide WordPress from the powered-by header when PHP exposes it.
		if ( function_exists( 'header_remove' ) ) {
			@header_remove( 'X-Powered-By' );
		}
	}

	public function admin_notice_urls() {
		if ( ! current_user_can( 'mvn_configure' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || empty( $screen->id ) || false === strpos( $screen->id, 'mvn-hardening' ) ) {
			return;
		}
		$urls = $this->public_urls();
		if ( empty( $urls['enabled'] ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>مسیرهای مخفی وردپرس:</strong> ';
		echo 'ورود: <code dir="ltr">' . esc_html( $urls['login_url'] ) . '</code>';
		if ( ! empty( $urls['admin_slug'] ) ) {
			echo ' | پیشخوان: <code dir="ltr">' . esc_html( $urls['admin_url'] ) . '</code>';
		}
		echo ' — این آدرس‌ها را ذخیره کنید؛ <code>wp-login.php</code> دیگر کار نمی‌کند.</p></div>';
	}

	/* ===================== helpers ===================== */

	/**
	 * @param string $slug Login slug.
	 * @return bool
	 */
	private function request_is_login_slug( $slug ) {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$home = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$home = untrailingslashit( $home );
		if ( $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		$path = trim( $path, '/' );
		return ( strtolower( $path ) === strtolower( $slug ) );
	}

	/**
	 * @return bool
	 */
	private function request_targets_wp_login() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = strtolower( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		if ( false !== strpos( $path, 'wp-login.php' ) ) {
			return true;
		}
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? strtolower( (string) $_SERVER['SCRIPT_NAME'] ) : '';
		return false !== strpos( $script, 'wp-login.php' );
	}

	/**
	 * @return bool
	 */
	private function request_targets_wp_admin() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = strtolower( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		return (bool) preg_match( '#/wp-admin(/|$)#', $path );
	}

	/**
	 * @param string $slug Admin slug.
	 * @return bool
	 */
	private function request_uses_admin_slug( $slug ) {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = strtolower( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$slug = strtolower( $slug );
		return (bool) preg_match( '#/' . preg_quote( $slug, '#' ) . '(/|$)#', $path );
	}

	/**
	 * @return bool
	 */
	private function is_admin_ajax_or_post() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? strtolower( (string) wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return (bool) preg_match( '#/wp-admin/admin-(ajax|post)\.php$#', $path );
	}

	/**
	 * @return bool
	 */
	private static function is_cli_or_cron() {
		return ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( defined( 'DOING_CRON' ) && DOING_CRON )
			|| ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() );
	}

	private function deny_404() {
		status_header( 404 );
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=UTF-8' );
		}
		global $wp_query;
		if ( isset( $wp_query ) && is_object( $wp_query ) && method_exists( $wp_query, 'set_404' ) ) {
			$wp_query->set_404();
			$template = get_query_template( '404' );
			if ( $template && is_readable( $template ) ) {
				include $template;
				exit;
			}
		}
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>404</title></head><body><h1>404 Not Found</h1></body></html>';
		exit;
	}

	/**
	 * Maintain optional Apache rewrite for custom admin slug.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function sync_htaccess_rules( array $settings ) {
		$ht = trailingslashit( ABSPATH ) . '.htaccess';
		if ( ! is_writable( dirname( $ht ) ) && ! ( is_file( $ht ) && is_writable( $ht ) ) ) {
			return;
		}
		$current = is_file( $ht ) ? (string) @file_get_contents( $ht ) : '';
		$current = preg_replace( "/# BEGIN MVN Cloak.*?# END MVN Cloak\s*/s", '', $current );

		$block = '';
		if ( ! empty( $settings['enabled'] ) && ! empty( $settings['admin_slug'] ) ) {
			$slug = preg_replace( '#[^a-z0-9\-_]#', '', strtolower( (string) $settings['admin_slug'] ) );
			if ( $slug ) {
				$block  = "# BEGIN MVN Cloak\n";
				$block .= "<IfModule mod_rewrite.c>\n";
				$block .= "RewriteEngine On\n";
				$block .= 'RewriteRule ^' . $slug . '/?(.*)$ wp-admin/$1 [QSA,L]' . "\n";
				$block .= "</IfModule>\n";
				$block .= "# END MVN Cloak\n\n";
			}
		}

		$new = $block . ltrim( (string) $current );
		if ( $new !== $current ) {
			// Prefer atomic helper when path is inside ABSPATH.
			if ( function_exists( 'mvn_atomic_write' ) ) {
				mvn_atomic_write( $ht, $new, 0644 );
			} else {
				@file_put_contents( $ht, $new );
			}
		}
	}
}
