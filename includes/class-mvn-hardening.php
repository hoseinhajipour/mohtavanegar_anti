<?php
/**
 * Hardening — brute-force protection, XML-RPC block, file-edit disable, etc.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Hardening {

	/** @var MVN_Hardening */
	private static $instance = null;

	/** @var array<int,int> user_id => timestamp — newly registered in this request */
	private $new_user_guard = array();

	/** @var bool */
	private $stripping_role = false;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function defaults() {
		return array(
			'block_xmlrpc'          => 1,
			'disable_file_edit'     => 1,
			'disable_file_mods'     => 0,
			'hide_wp_version'       => 1,
			'block_user_enum'       => 1,
			'login_brute_force'     => 1,
			'login_max_attempts'    => 5,
			'login_lockout_minutes' => 30,
			'disable_app_passwords' => 0,
			'remove_really_simple'  => 1,
			'secure_headers'        => 1,
			'disable_comments'     => 0,
			'block_external_http'  => 0,
			'block_privileged_signup' => 0,
		);
	}

	public function settings() {
		$saved = get_option( MVN_OPTION_HARDENING, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return array_merge( self::defaults(), $saved );
	}

	public function save( $input ) {
		$defaults = self::defaults();
		$out      = array();
		foreach ( $defaults as $key => $def ) {
			if ( in_array( $key, array( 'login_max_attempts', 'login_lockout_minutes' ), true ) ) {
				$out[ $key ] = isset( $input[ $key ] ) ? max( 1, (int) $input[ $key ] ) : $def;
			} else {
				$out[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
			}
		}
		update_option( MVN_OPTION_HARDENING, $out, false );
		return $out;
	}

	public function boot() {
		$s = $this->settings();

		if ( ! empty( $s['block_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_xmlrpc_server_class', array( $this, 'disable_xmlrpc_class' ) );
			add_action( 'init', array( $this, 'block_xmlrpc_request' ), 0 );
			add_filter( 'xmlrpc_methods', array( $this, 'empty_xmlrpc_methods' ) );
		}

		if ( ! empty( $s['disable_file_edit'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		if ( ! empty( $s['disable_file_mods'] ) && ! defined( 'DISALLOW_FILE_MODS' ) ) {
			define( 'DISALLOW_FILE_MODS', true );
		}

		// Outbound HTTP blocking is handled by MVN_Http_Guard (selective block/allow).
		// Do not define WP_HTTP_BLOCK_EXTERNAL here — it would bypass the allowlist UI.

		if ( ! empty( $s['hide_wp_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( ! empty( $s['block_user_enum'] ) ) {
			add_filter( 'redirect_canonical', array( $this, 'block_author_enum' ), 10, 2 );
			add_action( 'init', array( $this, 'block_rest_users' ) );
		}

		if ( ! empty( $s['login_brute_force'] ) ) {
			add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
			add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 3 );
			add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 2 );
		}

		if ( ! empty( $s['disable_app_passwords'] ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		if ( ! empty( $s['remove_really_simple'] ) ) {
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );
			remove_action( 'wp_head', 'wp_shortlink_wp_head' );
			remove_action( 'wp_head', 'rest_output_link_wp_head' );
			remove_action( 'template_redirect', 'rest_output_link_header', 11 );
		}

		if ( ! empty( $s['secure_headers'] ) ) {
			add_action( 'send_headers', array( $this, 'send_secure_headers' ) );
		}

		if ( ! empty( $s['disable_comments'] ) ) {
			add_action( 'admin_init', array( $this, 'disable_comments_post_types' ) );
			add_filter( 'comments_open', '__return_false', 20, 2 );
			add_filter( 'pings_open', '__return_false', 20, 2 );
			add_filter( 'comments_array', '__return_empty_array', 10, 2 );
			add_action( 'wp_loaded', array( $this, 'block_comment_post_endpoint' ) );
			add_action( 'admin_menu', array( $this, 'remove_comments_admin_menu' ) );
			add_action( 'wp_dashboard_setup', array( $this, 'remove_comments_dashboard' ) );
			add_filter( 'rest_endpoints', array( $this, 'remove_comments_rest' ) );
			add_filter( 'xmlrpc_methods', array( $this, 'remove_comments_xmlrpc' ), 20 );
			add_action( 'admin_bar_menu', array( $this, 'remove_comments_admin_bar' ), 999 );
			add_filter( 'feed_links_show_comments_feed', '__return_false' );
		}

		if ( ! empty( $s['block_privileged_signup'] ) ) {
			add_filter( 'pre_option_default_role', array( $this, 'safe_default_role' ) );
			add_action( 'user_register', array( $this, 'guard_new_user_roles' ), 1 );
			add_action( 'set_user_role', array( $this, 'guard_set_user_role' ), 10, 3 );
			add_action( 'add_user_role', array( $this, 'guard_add_user_role' ), 10, 2 );
			add_filter( 'editable_roles', array( $this, 'filter_new_user_editable_roles' ) );
			add_filter( 'registration_errors', array( $this, 'block_privileged_registration_errors' ), 10, 3 );
			add_filter( 'user_profile_update_errors', array( $this, 'block_privileged_user_create_errors' ), 10, 3 );
			add_filter( 'rest_pre_insert_user', array( $this, 'block_privileged_rest_user' ), 10, 2 );
		}
	}

	public function disable_xmlrpc_class( $class ) {
		return 'MVN_Disabled_XMLRPC';
	}

	public function empty_xmlrpc_methods( $methods ) {
		return array();
	}

	public function block_xmlrpc_request() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=UTF-8' );
			echo 'XML-RPC is disabled.';
			exit;
		}
		// Also catch direct hits to xmlrpc.php that somehow bypass the constant.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( false !== stripos( $uri, 'xmlrpc.php' ) ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=UTF-8' );
			echo 'XML-RPC is disabled.';
			exit;
		}
	}

	public function block_author_enum( $redirect, $requested ) {
		if ( is_admin() ) {
			return $redirect;
		}
		if ( isset( $_GET['author'] ) && preg_match( '/\d/', (string) $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
		return $redirect;
	}

	public function block_rest_users() {
		add_filter(
			'rest_endpoints',
			function ( $endpoints ) {
				if ( isset( $endpoints['/wp/v2/users'] ) ) {
					unset( $endpoints['/wp/v2/users'] );
				}
				if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
					unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
				}
				return $endpoints;
			}
		);
	}

	/* ---------- Brute-force ---------- */

	private function lockout_key( $ip ) {
		return 'mvn_lock_' . md5( $ip );
	}

	private function attempts_key( $ip ) {
		return 'mvn_att_' . md5( $ip );
	}

	public function on_login_failed( $username ) {
		$s   = $this->settings();
		$ip  = mvn_get_ip();
		$key = $this->attempts_key( $ip );
		$n   = (int) get_transient( $key );
		$n++;
		$window = max( 5, (int) $s['login_lockout_minutes'] ) * MINUTE_IN_SECONDS;
		set_transient( $key, $n, $window );
		if ( $n >= (int) $s['login_max_attempts'] ) {
			set_transient( $this->lockout_key( $ip ), time() + $window, $window );
			mvn_log( "Login lockout for IP {$ip} after {$n} failures (user={$username})" );
		}
	}

	public function check_lockout( $user, $username, $password ) {
		$ip = mvn_get_ip();
		$until = get_transient( $this->lockout_key( $ip ) );
		if ( $until ) {
			$mins = max( 1, (int) ceil( ( (int) $until - time() ) / 60 ) );
			return new WP_Error(
				'mvn_locked',
				sprintf(
					/* translators: %d minutes */
					'به دلیل تلاش‌های ناموفق زیاد، ورود از این IP برای حدود %d دقیقه مسدود است.',
					$mins
				)
			);
		}
		return $user;
	}

	public function on_login_success( $user_login, $user ) {
		$ip = mvn_get_ip();
		delete_transient( $this->attempts_key( $ip ) );
		delete_transient( $this->lockout_key( $ip ) );
	}

	public function send_secure_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'X-XSS-Protection: 0' );
	}

	/* ---------- Disable comments site-wide ---------- */

	public function disable_comments_post_types() {
		$types = get_post_types( array( 'public' => true ), 'names' );
		foreach ( $types as $type ) {
			if ( post_type_supports( $type, 'comments' ) ) {
				remove_post_type_support( $type, 'comments' );
				remove_post_type_support( $type, 'trackbacks' );
			}
		}
	}

	public function block_comment_post_endpoint() {
		if ( ! is_admin() && isset( $_SERVER['REQUEST_URI'] ) && false !== stripos( (string) $_SERVER['REQUEST_URI'], 'wp-comments-post.php' ) ) {
			wp_die( esc_html__( 'ثبت نظر در این سایت غیرفعال است.', 'mvn' ), 403 );
		}
	}

	public function remove_comments_admin_menu() {
		remove_menu_page( 'edit-comments.php' );
	}

	public function remove_comments_dashboard() {
		remove_meta_box( 'dashboard_recent_comments', 'dashboard', 'normal' );
	}

	public function remove_comments_rest( $endpoints ) {
		foreach ( array_keys( (array) $endpoints ) as $route ) {
			if ( 0 === strpos( (string) $route, '/wp/v2/comments' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	public function remove_comments_xmlrpc( $methods ) {
		unset( $methods['wp.newComment'], $methods['wp.getComments'], $methods['wp.deleteComment'], $methods['wp.editComment'], $methods['wp.getComment'], $methods['wp.getCommentStatusList'], $methods['wp.getCommentCount'] );
		return $methods;
	}

	public function remove_comments_admin_bar( $wp_admin_bar ) {
		if ( is_object( $wp_admin_bar ) ) {
			$wp_admin_bar->remove_node( 'comments' );
		}
	}

	/* ---------- Block privileged new users (admin / author) ---------- */

	/**
	 * Roles that must not be granted to newly registered/created users.
	 *
	 * @return string[]
	 */
	private function blocked_signup_roles() {
		return apply_filters( 'mvn_blocked_signup_roles', array( 'administrator', 'author' ) );
	}

	private function is_blocked_signup_role( $role ) {
		return in_array( (string) $role, $this->blocked_signup_roles(), true );
	}

	private function safe_fallback_role() {
		$role = get_option( 'default_role', 'subscriber' );
		if ( $this->is_blocked_signup_role( $role ) ) {
			return 'subscriber';
		}
		return $role ? $role : 'subscriber';
	}

	public function safe_default_role( $value ) {
		if ( $this->is_blocked_signup_role( $value ) ) {
			return 'subscriber';
		}
		return $value;
	}

	public function guard_new_user_roles( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		$this->new_user_guard[ $user_id ] = time();
		$this->strip_privileged_roles( $user_id );
	}

	public function guard_set_user_role( $user_id, $role, $old_roles ) {
		if ( $this->stripping_role || ! $this->is_blocked_signup_role( $role ) ) {
			return;
		}
		$user_id = (int) $user_id;
		// فقط کاربر تازه‌ساخته‌شده در همین درخواست / ثبت‌نام — ارتقای بعدی کاربران قدیمی مجاز می‌ماند.
		if ( empty( $this->new_user_guard[ $user_id ] ) && ! $this->is_new_user_creation_request() ) {
			return;
		}
		$this->strip_privileged_roles( $user_id );
		mvn_log( "Blocked privileged role '{$role}' on new user #{$user_id}" );
	}

	public function guard_add_user_role( $user_id, $role ) {
		if ( $this->stripping_role || ! $this->is_blocked_signup_role( $role ) ) {
			return;
		}
		$user_id = (int) $user_id;
		if ( empty( $this->new_user_guard[ $user_id ] ) && ! $this->is_new_user_creation_request() ) {
			return;
		}
		$user = new WP_User( $user_id );
		$this->stripping_role = true;
		$user->remove_role( $role );
		$this->stripping_role = false;
		if ( empty( $user->roles ) ) {
			$this->stripping_role = true;
			$user->set_role( $this->safe_fallback_role() );
			$this->stripping_role = false;
		}
		mvn_log( "Removed privileged role '{$role}' from new user #{$user_id}" );
	}

	private function strip_privileged_roles( $user_id ) {
		$user = new WP_User( (int) $user_id );
		if ( ! $user->exists() ) {
			return;
		}
		$had = false;
		$this->stripping_role = true;
		foreach ( $this->blocked_signup_roles() as $role ) {
			if ( in_array( $role, (array) $user->roles, true ) ) {
				$user->remove_role( $role );
				$had = true;
			}
		}
		if ( $had || empty( $user->roles ) ) {
			$user->set_role( $this->safe_fallback_role() );
		}
		$this->stripping_role = false;
	}

	private function is_new_user_creation_request() {
		if ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) {
			return false;
		}
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( in_array( $action, array( 'createuser', 'register', 'registeruser' ), true ) ) {
			return true;
		}
		global $pagenow;
		if ( is_admin() && isset( $pagenow ) && 'user-new.php' === $pagenow ) {
			return true;
		}
		if ( did_action( 'register_post' ) || did_action( 'register_new_user' ) || did_action( 'woocommerce_created_customer' ) ) {
			return true;
		}
		return false;
	}

	public function filter_new_user_editable_roles( $roles ) {
		if ( ! is_array( $roles ) ) {
			return $roles;
		}
		global $pagenow;
		$on_new = ( isset( $pagenow ) && 'user-new.php' === $pagenow )
			|| ( isset( $_REQUEST['action'] ) && 'createuser' === sanitize_key( wp_unslash( $_REQUEST['action'] ) ) ); // phpcs:ignore
		if ( ! $on_new ) {
			return $roles;
		}
		foreach ( $this->blocked_signup_roles() as $role ) {
			unset( $roles[ $role ] );
		}
		return $roles;
	}

	public function block_privileged_registration_errors( $errors, $sanitized_user_login, $user_email ) {
		$role = isset( $_REQUEST['role'] ) ? sanitize_key( wp_unslash( $_REQUEST['role'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( $this->is_blocked_signup_role( $role ) ) {
			$errors->add( 'mvn_role_blocked', 'ثبت‌نام با نقش مدیر یا نویسنده در این سایت مجاز نیست.' );
		}
		return $errors;
	}

	public function block_privileged_user_create_errors( $errors, $update, $user ) {
		if ( $update ) {
			return $errors;
		}
		$role = '';
		if ( is_object( $user ) && ! empty( $user->role ) ) {
			$role = $user->role;
		} elseif ( isset( $_REQUEST['role'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$role = sanitize_key( wp_unslash( $_REQUEST['role'] ) );
		}
		if ( $this->is_blocked_signup_role( $role ) ) {
			$errors->add( 'mvn_role_blocked', 'ایجاد کاربر جدید با نقش مدیر یا نویسنده غیرفعال است.', array( 'form-field' => 'role' ) );
		}
		return $errors;
	}

	public function block_privileged_rest_user( $prepared_user, $request ) {
		if ( is_wp_error( $prepared_user ) ) {
			return $prepared_user;
		}
		// فقط ایجاد کاربر جدید (نه ویرایش).
		if ( $request instanceof WP_REST_Request && $request->get_param( 'id' ) ) {
			return $prepared_user;
		}
		$roles = array();
		if ( $request instanceof WP_REST_Request ) {
			$roles = (array) $request->get_param( 'roles' );
		}
		foreach ( $roles as $role ) {
			if ( $this->is_blocked_signup_role( $role ) ) {
				return new WP_Error(
					'mvn_role_blocked',
					'ایجاد کاربر جدید با نقش مدیر یا نویسنده غیرفعال است.',
					array( 'status' => 403 )
				);
			}
		}
		return $prepared_user;
	}
}

/**
 * Dummy XML-RPC server class used when XML-RPC is fully disabled.
 */
class MVN_Disabled_XMLRPC {
	public function serve_request() {
		status_header( 403 );
		echo 'XML-RPC is disabled.';
		exit;
	}
}
