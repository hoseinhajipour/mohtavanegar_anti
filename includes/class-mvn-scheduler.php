<?php
/**
 * Background scan scheduler — opt-in, cron-only workers (does not slow front-end).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Scheduler {

	const QUICK   = 'mvn_security_quick_scan';
	const FULL    = 'mvn_security_full_scan';
	const WORKER  = 'mvn_security_scan_worker';
	const OPTION  = 'mvn_schedule_enabled';
	const ENSURE_TRANSIENT = 'mvn_schedule_ensured';

	public static function boot() {
		add_action( self::QUICK, array( __CLASS__, 'run_quick' ) );
		add_action( self::FULL, array( __CLASS__, 'run_full' ) );
		add_action( self::WORKER, array( __CLASS__, 'work' ) );
		// Only ensure schedules during cron / admin — never on every public page view.
		if ( self::is_background_context() ) {
			add_action( 'init', array( __CLASS__, 'ensure' ), 20 );
		}
	}

	/**
	 * Cron, WP-CLI, or wp-admin (not public front-end HTML).
	 */
	public static function is_background_context() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return true;
		}
		if ( is_admin() ) {
			return true;
		}
		return false;
	}

	/**
	 * Auto background scans are OFF by default (prevents site-wide slowdown).
	 */
	public static function is_enabled() {
		return (bool) apply_filters( 'mvn_schedule_enabled', (bool) get_option( self::OPTION, false ) );
	}

	public static function set_enabled( $on ) {
		$on = (bool) $on;
		update_option( self::OPTION, $on ? 1 : 0, false );
		if ( $on ) {
			delete_transient( self::ENSURE_TRANSIENT );
			self::ensure( true );
		} else {
			self::deactivate();
		}
		return $on;
	}

	public static function ensure( $force = false ) {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! $force && get_transient( self::ENSURE_TRANSIENT ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::QUICK ) ) {
			wp_schedule_single_event( time() + DAY_IN_SECONDS, self::QUICK );
		}
		if ( ! wp_next_scheduled( self::FULL ) ) {
			wp_schedule_single_event( time() + WEEK_IN_SECONDS, self::FULL );
		}
		set_transient( self::ENSURE_TRANSIENT, 1, 12 * HOUR_IN_SECONDS );
	}

	public static function run_quick() {
		if ( ! self::is_enabled() ) {
			return;
		}
		wp_schedule_single_event( time() + DAY_IN_SECONDS, self::QUICK );
		self::start( false );
	}

	public static function run_full() {
		if ( ! self::is_enabled() ) {
			return;
		}
		wp_schedule_single_event( time() + WEEK_IN_SECONDS, self::FULL );
		self::start( true );
	}

	private static function start( $full ) {
		// Never start a heavy scan from a random front-end hit.
		if ( ! self::is_background_context() ) {
			return;
		}
		$state = MVN_Scanner::get_state();
		if ( ! empty( $state['status'] ) && in_array( $state['status'], array( 'running', 'paused' ), true ) ) {
			return;
		}
		$result = MVN_Scanner::start(
			array(
				'scope'       => 'wp-content',
				'full'        => $full,
				'incremental' => ! $full,
				'scan_db'     => true,
				'scan_as'     => false,
				'scan_core'   => false,
				'scan_repo'   => false,
			)
		);
		if ( ! is_wp_error( $result ) ) {
			// Wider spacing so cron does not saturate the site.
			wp_schedule_single_event( time() + 90, self::WORKER );
		}
	}

	public static function work() {
		if ( ! self::is_background_context() ) {
			return;
		}
		@set_time_limit( 60 );
		$state = MVN_Scanner::tick();
		if ( ! empty( $state['status'] ) && 'running' === $state['status'] ) {
			wp_schedule_single_event( time() + 90, self::WORKER );
		}
	}

	public static function status() {
		$path = str_replace( array( "\r", "\n", '"' ), array( '', '', '\"' ), ABSPATH );
		return array(
			'enabled'       => self::is_enabled(),
			'quick_next'    => wp_next_scheduled( self::QUICK ),
			'full_next'     => wp_next_scheduled( self::FULL ),
			'worker_next'   => wp_next_scheduled( self::WORKER ),
			'cron_disabled' => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'system_cron'   => '*/5 * * * * wp --path="' . $path . '" cron event run --due-now --quiet',
		);
	}

	public static function deactivate() {
		foreach ( array( self::QUICK, self::FULL, self::WORKER ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		delete_transient( self::ENSURE_TRANSIENT );
	}
}
