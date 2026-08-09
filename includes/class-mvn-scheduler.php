<?php
/**
 * Chained single-event scheduled scans (daily incremental, weekly full).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Scheduler {

	const QUICK  = 'mvn_security_quick_scan';
	const FULL   = 'mvn_security_full_scan';
	const WORKER = 'mvn_security_scan_worker';

	public static function boot() {
		add_action( self::QUICK, array( __CLASS__, 'run_quick' ) );
		add_action( self::FULL, array( __CLASS__, 'run_full' ) );
		add_action( self::WORKER, array( __CLASS__, 'work' ) );
		add_action( 'init', array( __CLASS__, 'ensure' ), 20 );
	}

	public static function ensure() {
		if ( ! wp_next_scheduled( self::QUICK ) ) {
			wp_schedule_single_event( time() + HOUR_IN_SECONDS, self::QUICK );
		}
		if ( ! wp_next_scheduled( self::FULL ) ) {
			wp_schedule_single_event( time() + DAY_IN_SECONDS, self::FULL );
		}
	}

	public static function run_quick() {
		wp_schedule_single_event( time() + DAY_IN_SECONDS, self::QUICK );
		self::start( false );
	}

	public static function run_full() {
		wp_schedule_single_event( time() + WEEK_IN_SECONDS, self::FULL );
		self::start( true );
	}

	private static function start( $full ) {
		$state = MVN_Scanner::get_state();
		if ( ! empty( $state['status'] ) && in_array( $state['status'], array( 'running', 'paused' ), true ) ) {
			return;
		}
		$result = MVN_Scanner::start(
			array( 'scope' => 'all', 'full' => $full, 'incremental' => ! $full, 'scan_db' => true, 'scan_as' => true )
		);
		if ( ! is_wp_error( $result ) ) {
			wp_schedule_single_event( time() + 15, self::WORKER );
		}
	}

	public static function work() {
		$state = MVN_Scanner::tick();
		if ( ! empty( $state['status'] ) && 'running' === $state['status'] ) {
			wp_schedule_single_event( time() + 15, self::WORKER );
		}
	}

	public static function status() {
		// This is display-only. Do not depend on shell functions that hosts may disable.
		$path = str_replace( array( "\r", "\n", '"' ), array( '', '', '\"' ), ABSPATH );
		return array(
			'quick_next' => wp_next_scheduled( self::QUICK ),
			'full_next' => wp_next_scheduled( self::FULL ),
			'cron_disabled' => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'system_cron' => '*/5 * * * * wp --path="' . $path . '" cron event run --due-now --quiet',
		);
	}

	public static function deactivate() {
		foreach ( array( self::QUICK, self::FULL, self::WORKER ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}
}
