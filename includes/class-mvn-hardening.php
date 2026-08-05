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
