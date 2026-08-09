<?php
/**
 * Outbound HTTP guard — log, block, and allow external requests.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Http_Guard {

	const OPTION_LOG     = 'mvn_http_outbound_log';
	const OPTION_BLOCKED = 'mvn_http_blocked_hosts';
	const OPTION_ALLOWED = 'mvn_http_allowed_hosts';
	const MAX_LOG        = 200;

	/** @var MVN_Http_Guard */
	private static $instance = null;

	/** @var bool Avoid re-entrancy while writing options */
	private $logging = false;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot() {
		add_filter( 'pre_http_request', array( $this, 'filter_request' ), 4, 3 );

		/*
		 * If wp-config already defines WP_HTTP_BLOCK_EXTERNAL, sync our allowlist
		 * into WP_ACCESSIBLE_HOSTS so «آنبلاک» still works with core's blocker.
		 */
		if ( defined( 'WP_HTTP_BLOCK_EXTERNAL' ) && WP_HTTP_BLOCK_EXTERNAL && ! defined( 'WP_ACCESSIBLE_HOSTS' ) ) {
			$allowed = self::allowed_hosts();
			if ( $allowed ) {
				define( 'WP_ACCESSIBLE_HOSTS', implode( ',', $allowed ) );
			}
		}
	}

	/**
	 * Log every outbound request and enforce block/allow rules.
	 *
	 * @param false|array|WP_Error $preempt
	 * @param array                $args
	 * @param string               $url
	 * @return false|array|WP_Error
	 */
	public function filter_request( $preempt, $args, $url ) {
		if ( false !== $preempt ) {
			return $preempt;
		}

		$host = $this->host_from_url( $url );
		if ( ! $host ) {
			return $preempt;
		}

		$local = $this->is_local_host( $host );
		if ( ! $local ) {
			$this->record(
				$host,
				$url,
				isset( $args['method'] ) ? (string) $args['method'] : 'GET'
			);
		}

		if ( $local ) {
			return $preempt;
		}

		if ( $this->should_block( $host ) ) {
			return new WP_Error(
				'mvn_http_blocked',
				'درخواست HTTP خارجی توسط آنتی‌ویروس محتوانگار مسدود شد: ' . $host
			);
		}

		return $preempt;
	}

	/**
	 * @param string $host
	 * @return bool
	 */
	public function should_block( $host ) {
		$host = strtolower( (string) $host );
		if ( ! $host || $this->is_local_host( $host ) ) {
			return false;
		}

		// Explicit allow always wins (آنبلاک).
		foreach ( self::base_allowed_hosts() as $a ) {
			if ( $this->host_matches( $host, $a ) ) {
				return false;
			}
		}

		foreach ( self::blocked_hosts() as $b ) {
			if ( $this->host_matches( $host, $b ) ) {
				return true;
			}
		}

		// Perf optimizer blocklist.
		if ( class_exists( 'MVN_Perf' ) ) {
			foreach ( MVN_Perf::blocked_hosts() as $b ) {
				if ( $this->host_matches( $host, $b ) ) {
					return true;
				}
			}
		}

		// Declared updater origins bypass only global block-all, never an explicit block.
		foreach ( self::installed_update_hosts() as $update_host ) {
			if ( $this->host_matches( $host, $update_host ) ) {
				return false;
			}
		}

		$hard = MVN_Hardening::instance()->settings();
		if ( ! empty( $hard['block_external_http'] ) ) {
			return true;
		}

		if ( defined( 'WP_HTTP_BLOCK_EXTERNAL' ) && WP_HTTP_BLOCK_EXTERNAL ) {
			return true;
		}

		return false;
	}

	/**
	 * Effective status for UI: blocked | allowed | local.
	 *
	 * @param string $host
	 * @return string
	 */
	public function host_status( $host ) {
		$host = strtolower( (string) $host );
		if ( $this->is_local_host( $host ) ) {
			return 'local';
		}
		return $this->should_block( $host ) ? 'blocked' : 'allowed';
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function log_entries() {
		$log = get_option( self::OPTION_LOG, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$out = array_values( $log );
		usort(
			$out,
			static function ( $a, $b ) {
				$ta = isset( $a['last_seen'] ) ? (int) $a['last_seen'] : 0;
				$tb = isset( $b['last_seen'] ) ? (int) $b['last_seen'] : 0;
				return $tb <=> $ta;
			}
		);
		return $out;
	}

	/**
	 * @return string[]
	 */
	public static function blocked_hosts() {
		return self::normalize_host_list( get_option( self::OPTION_BLOCKED, array() ) );
	}

	/**
	 * @return string[]
	 */
	public static function allowed_hosts() {
		return self::normalize_host_list( array_merge( self::base_allowed_hosts(), self::installed_update_hosts() ) );
	}

	private static function base_allowed_hosts() {
		$required = class_exists( 'MVN_URL_Trust' ) ? MVN_URL_Trust::allowed_hosts() : array( 'api.wordpress.org', 'downloads.wordpress.org' );
		return self::normalize_host_list( array_merge( get_option( self::OPTION_ALLOWED, array() ), $required ) );
	}

	/**
	 * Trust updater origins explicitly declared by installed themes/plugins.
	 *
	 * ThemeURI is included because legacy custom updaters often predate Update URI.
	 * Installing the extension is already equivalent to trusting its PHP code.
	 *
	 * @return string[]
	 */
	private static function installed_update_hosts() {
		static $hosts = null;
		if ( null !== $hosts ) {
			return $hosts;
		}
		$hosts = get_transient( 'mvn_installed_update_hosts' );
		if ( is_array( $hosts ) ) {
			return $hosts;
		}
		$hosts = array();
		if ( function_exists( 'wp_get_themes' ) ) {
			foreach ( wp_get_themes() as $theme ) {
				foreach ( array( 'UpdateURI', 'ThemeURI' ) as $header ) {
					$url  = (string) $theme->get( $header );
					$host = $url ? wp_parse_url( $url, PHP_URL_HOST ) : '';
					if ( $host ) {
						$hosts[] = strtolower( $host );
					}
				}
			}
		}
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $plugin ) {
				$url  = isset( $plugin['UpdateURI'] ) ? (string) $plugin['UpdateURI'] : '';
				$host = $url ? wp_parse_url( $url, PHP_URL_HOST ) : '';
				if ( $host ) {
					$hosts[] = strtolower( $host );
				}
			}
		}
		$hosts = self::normalize_host_list( array_unique( $hosts ) );
		set_transient( 'mvn_installed_update_hosts', $hosts, 6 * HOUR_IN_SECONDS );
		return $hosts;
	}

	/**
	 * Block a host (always deny, even if global block is off).
	 *
	 * @param string $host
	 * @return true|WP_Error
	 */
	public static function block_host( $host ) {
		$host = self::sanitize_host( $host );
		if ( ! $host ) {
			return new WP_Error( 'mvn_bad_host', 'دامنه نامعتبر است.' );
		}
		$guard = self::instance();
		if ( $guard->is_local_host( $host ) ) {
			return new WP_Error( 'mvn_local_host', 'دامنه خود سایت قابل مسدودسازی نیست.' );
		}

		$blocked   = self::blocked_hosts();
		$blocked[] = $host;
		update_option( self::OPTION_BLOCKED, array_values( array_unique( $blocked ) ), false );

		$allowed = array_values( array_filter(
			self::allowed_hosts(),
			static function ( $h ) use ( $host ) {
				return $h !== $host;
			}
		) );
		update_option( self::OPTION_ALLOWED, $allowed, false );

		self::touch_log_status( $host );
		mvn_log( "HTTP host blocked: {$host}" );
		return true;
	}

	/**
	 * Unblock / allow a host.
	 * Always adds to allowlist so آنبلاک wins over global block and blocklists.
	 *
	 * @param string $host
	 * @return true|WP_Error
	 */
	public static function unblock_host( $host ) {
		$host = self::sanitize_host( $host );
		if ( ! $host ) {
			return new WP_Error( 'mvn_bad_host', 'دامنه نامعتبر است.' );
		}

		// Remove from our blocklist (exact + rules that only match this host).
		$blocked = array_values( array_filter(
			self::blocked_hosts(),
			static function ( $h ) use ( $host ) {
				return $h !== $host;
			}
		) );
		update_option( self::OPTION_BLOCKED, $blocked, false );

		// Also clear Perf module blocklist for this host.
		if ( class_exists( 'MVN_Perf' ) ) {
			$perf = array_values( array_filter(
				MVN_Perf::blocked_hosts(),
				static function ( $h ) use ( $host ) {
					return strtolower( (string) $h ) !== $host;
				}
			) );
			update_option( MVN_Perf::OPTION_BLOCK, $perf, false );
		}

		// Always allow explicitly — required when global external block is on.
		$allowed   = self::allowed_hosts();
		$allowed[] = $host;
		update_option( self::OPTION_ALLOWED, array_values( array_unique( $allowed ) ), false );

		self::touch_log_status( $host );
		mvn_log( "HTTP host unblocked/allowed: {$host}" );
		return true;
	}

	/**
	 * Manually add a host to the log (and optionally block).
	 *
	 * @param string $host
	 * @param bool   $block
	 * @return true|WP_Error
	 */
	public static function add_host( $host, $block = false ) {
		$host = self::sanitize_host( $host );
		if ( ! $host ) {
			return new WP_Error( 'mvn_bad_host', 'دامنه نامعتبر است.' );
		}
		self::instance()->record( $host, 'https://' . $host . '/', 'MANUAL' );
		if ( $block ) {
			return self::block_host( $host );
		}
		return true;
	}

	public static function clear_log() {
		delete_option( self::OPTION_LOG );
		return true;
	}

	/**
	 * Payload for admin UI / AJAX refresh.
	 *
	 * @return array<string,mixed>
	 */
	public static function admin_payload() {
		$hard = MVN_Hardening::instance()->settings();
		$guard = self::instance();
		$entries = array();
		foreach ( self::log_entries() as $row ) {
			$host = isset( $row['host'] ) ? (string) $row['host'] : '';
			if ( ! $host ) {
				continue;
			}
			$status = $guard->host_status( $host );
			$entries[] = array(
				'host'      => $host,
				'count'     => isset( $row['count'] ) ? (int) $row['count'] : 0,
				'method'    => isset( $row['method'] ) ? (string) $row['method'] : '',
				'last_url'  => isset( $row['last_url'] ) ? (string) $row['last_url'] : '',
				'last_seen' => isset( $row['last_seen'] ) ? (int) $row['last_seen'] : 0,
				'last_seen_human' => isset( $row['last_seen'] )
					? wp_date( 'Y-m-d H:i:s', (int) $row['last_seen'] )
					: '',
				'status'    => $status,
			);
		}

		return array(
			'entries'       => $entries,
			'blocked_hosts' => self::blocked_hosts(),
			'allowed_hosts' => self::allowed_hosts(),
			'global_block'  => ! empty( $hard['block_external_http'] )
				|| ( defined( 'WP_HTTP_BLOCK_EXTERNAL' ) && WP_HTTP_BLOCK_EXTERNAL ),
		);
	}

	/* ---------- internals ---------- */

	private function record( $host, $url, $method ) {
		if ( $this->logging ) {
			return;
		}
		$host = strtolower( (string) $host );
		if ( ! $host ) {
			return;
		}

		$this->logging = true;
		$log = get_option( self::OPTION_LOG, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$prev = isset( $log[ $host ] ) && is_array( $log[ $host ] ) ? $log[ $host ] : array();
		$log[ $host ] = array(
			'host'      => $host,
			'count'     => ( isset( $prev['count'] ) ? (int) $prev['count'] : 0 ) + 1,
			'method'    => strtoupper( (string) $method ),
			'last_url'  => self::truncate_url( $url ),
			'last_seen' => time(),
		);

		if ( count( $log ) > self::MAX_LOG ) {
			uasort(
				$log,
				static function ( $a, $b ) {
					$ta = isset( $a['last_seen'] ) ? (int) $a['last_seen'] : 0;
					$tb = isset( $b['last_seen'] ) ? (int) $b['last_seen'] : 0;
					return $ta <=> $tb;
				}
			);
			$log = array_slice( $log, -self::MAX_LOG, null, true );
		}

		update_option( self::OPTION_LOG, $log, false );
		$this->logging = false;
	}

	private static function touch_log_status( $host ) {
		$log = get_option( self::OPTION_LOG, array() );
		if ( ! is_array( $log ) || empty( $log[ $host ] ) ) {
			self::instance()->record( $host, 'https://' . $host . '/', 'MANUAL' );
		}
	}

	private function host_from_url( $url ) {
		$host = wp_parse_url( (string) $url, PHP_URL_HOST );
		return $host ? strtolower( (string) $host ) : '';
	}

	private function is_local_host( $host ) {
		$host = strtolower( (string) $host );
		if ( ! $host ) {
			return true;
		}
		if ( in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true ) ) {
			return true;
		}

		$candidates = array();
		foreach ( array( home_url(), site_url(), get_option( 'siteurl' ), get_option( 'home' ) ) as $u ) {
			$h = wp_parse_url( (string) $u, PHP_URL_HOST );
			if ( $h ) {
				$candidates[] = strtolower( (string) $h );
			}
		}
		$candidates = array_unique( array_filter( $candidates ) );
		foreach ( $candidates as $c ) {
			if ( $host === $c || $this->host_matches( $host, $c ) ) {
				return true;
			}
		}
		return false;
	}

	private function host_matches( $host, $rule ) {
		$host = strtolower( (string) $host );
		$rule = strtolower( (string) $rule );
		if ( ! $host || ! $rule ) {
			return false;
		}
		if ( $host === $rule ) {
			return true;
		}
		$suffix = '.' . $rule;
		return substr( $host, -strlen( $suffix ) ) === $suffix;
	}

	/**
	 * @param mixed $list
	 * @return string[]
	 */
	private static function normalize_host_list( $list ) {
		if ( ! is_array( $list ) ) {
			return array();
		}
		$out = array();
		foreach ( $list as $h ) {
			$h = self::sanitize_host( $h );
			if ( $h ) {
				$out[] = $h;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * @param string $host
	 * @return string
	 */
	private static function sanitize_host( $host ) {
		$host = strtolower( trim( (string) $host ) );
		$host = preg_replace( '#^https?://#i', '', $host );
		$host = preg_replace( '#/.*$#', '', $host );
		$host = preg_replace( '/:\d+$/', '', $host );
		$host = preg_replace( '/[^a-z0-9\.\-]/i', '', $host );
		$host = trim( (string) $host, '.' );
		return $host;
	}

	/**
	 * @param string $url
	 * @return string
	 */
	private static function truncate_url( $url ) {
		$url = (string) $url;
		if ( strlen( $url ) > 300 ) {
			return substr( $url, 0, 297 ) . '...';
		}
		return $url;
	}
}
