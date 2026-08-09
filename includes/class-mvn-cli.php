<?php
/**
 * Optional WP-CLI recovery commands.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_CLI {

	public function scan( $args, $assoc ) {
		$result = MVN_Scanner::start(
			array(
				'scope' => isset( $assoc['scope'] ) ? $assoc['scope'] : 'all',
				'full' => isset( $assoc['full'] ),
				'incremental' => ! isset( $assoc['full'] ),
				'scan_db' => true, 'scan_as' => true, 'scan_core' => true, 'scan_repo' => true,
			)
		);
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		$ticks = 0;
		while ( ! empty( $result['status'] ) && 'running' === $result['status'] && $ticks < 100000 ) {
			$result = MVN_Scanner::tick();
			$ticks++;
		}
		WP_CLI::success( 'Scan ' . $result['status'] . '; issues=' . count( MVN_Scanner::get_issues() ) );
	}

	public function status() {
		WP_CLI::print_value(
			wp_json_encode(
				array(
					'scan' => MVN_Scanner::get_state(),
					'incidents' => MVN_Incidents::all(),
					'signatures' => MVN_Signature_Pack::status(),
					'self_integrity' => MVN_Self_Integrity::verify(),
					'schedule' => MVN_Scheduler::status(),
				),
				JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE
			)
		);
	}

	/**
	 * List quarantine entries.
	 *
	 * ## EXAMPLES
	 * wp mvn quarantine-list
	 */
	public function quarantine_list() {
		WP_CLI\Utils\format_items( 'table', MVN_Quarantine::list_all(), array( 'id', 'rel', 'reason', 'created_at', 'size' ) );
	}

	public function quarantine_restore( $args, $assoc ) {
		if ( empty( $args[0] ) ) {
			WP_CLI::error( 'Quarantine ID required.' );
		}
		$result = MVN_Quarantine::restore( $args[0], isset( $assoc['force'] ) );
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		WP_CLI::success( 'Restored.' );
	}

	public function repair_verify() {
		WP_CLI::print_value( wp_json_encode( array( 'core' => MVN_Core_Repair::source_status(), 'self' => MVN_Self_Integrity::verify() ), JSON_PRETTY_PRINT ) );
	}
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	$mvn_cli = new MVN_CLI();
	WP_CLI::add_command( 'mvn scan', array( $mvn_cli, 'scan' ) );
	WP_CLI::add_command( 'mvn status', array( $mvn_cli, 'status' ) );
	WP_CLI::add_command( 'mvn quarantine list', array( $mvn_cli, 'quarantine_list' ) );
	WP_CLI::add_command( 'mvn quarantine restore', array( $mvn_cli, 'quarantine_restore' ) );
	WP_CLI::add_command( 'mvn repair verify', array( $mvn_cli, 'repair_verify' ) );
}
