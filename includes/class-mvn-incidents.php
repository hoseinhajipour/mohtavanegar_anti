<?php
/**
 * Persistent incident lifecycle and issue state store.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Incidents {

	const STATE_KEY = 'incidents';
	const ISSUES_KEY = 'issues_store';

	public static function store_issues( $issues ) {
		$issues = is_array( $issues ) ? array_values( $issues ) : array();
		mvn_state_write( self::ISSUES_KEY, $issues );
		// Keep a compact compatibility summary non-autoloaded.
		$summary = array_map(
			static function ( $issue ) {
				return array_intersect_key( $issue, array_flip( array( 'id', 'rel', 'sig', 'label', 'severity', 'confidence', 'action', 'source' ) ) );
			},
			array_slice( $issues, 0, 100 )
		);
		update_option( MVN_OPTION_ISSUES, $summary, false );
	}

	public static function issues() {
		$issues = mvn_state_read( self::ISSUES_KEY, null );
		return is_array( $issues ) ? $issues : (array) get_option( MVN_OPTION_ISSUES, array() );
	}

	public static function sync_scan( $issues, $scan_id = '' ) {
		$all  = mvn_state_read( self::STATE_KEY, array() );
		$seen = array();
		foreach ( (array) $issues as $issue ) {
			$id = isset( $issue['id'] ) ? $issue['id'] : md5( wp_json_encode( $issue ) );
			$seen[ $id ] = true;
			if ( empty( $all[ $id ] ) ) {
				$all[ $id ] = array(
					'id' => $id, 'status' => 'open', 'opened_at' => gmdate( 'c' ),
					'history' => array( array( 'at' => gmdate( 'c' ), 'status' => 'open', 'actor' => 'scanner' ) ),
				);
			}
			$all[ $id ]['finding']   = $issue;
			$all[ $id ]['last_seen'] = gmdate( 'c' );
			$all[ $id ]['scan_id']   = $scan_id;
		}
		foreach ( $all as $id => &$incident ) {
			if ( empty( $seen[ $id ] ) && in_array( $incident['status'], array( 'quarantined', 'fixed' ), true ) ) {
				self::transition_row( $incident, 'verified', 'post-fix-scan', array() );
			}
		}
		unset( $incident );
		mvn_state_write( self::STATE_KEY, $all );
		return $all;
	}

	public static function transition( $id, $status, $actor = 'system', $context = array() ) {
		if ( ! in_array( $status, array( 'open', 'quarantined', 'fixed', 'verified', 'failed', 'ignored' ), true ) ) {
			return false;
		}
		$all = mvn_state_read( self::STATE_KEY, array() );
		if ( empty( $all[ $id ] ) ) {
			return false;
		}
		self::transition_row( $all[ $id ], $status, $actor, $context );
		return mvn_state_write( self::STATE_KEY, $all );
	}

	private static function transition_row( &$row, $status, $actor, $context ) {
		$row['status'] = $status;
		$row['updated_at'] = gmdate( 'c' );
		$row['history'][] = array( 'at' => gmdate( 'c' ), 'status' => $status, 'actor' => $actor, 'context' => $context );
		$row['history'] = array_slice( $row['history'], -50 );
	}

	public static function all() {
		return mvn_state_read( self::STATE_KEY, array() );
	}
}
