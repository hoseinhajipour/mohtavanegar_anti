<?php
/**
 * Structured security event log (file + compact option ring).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Security_Log {

	const OPTION = 'mvn_security_log_meta';
	const RING   = 80;

	/**
	 * @param string $action Event name.
	 * @param string $target Path / option / hook.
	 * @param string $result Result code.
	 */
	public static function write( $action, $target = '', $result = 'ok' ) {
		mvn_ensure_data_dirs();
		$row = array(
			'timestamp' => gmdate( 'c' ),
			'user_id'   => function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0,
			'ip'        => function_exists( 'mvn_get_ip' ) ? mvn_get_ip() : '',
			'action'    => sanitize_key( $action ),
			'target'    => substr( (string) $target, 0, 400 ),
			'result'    => substr( (string) $result, 0, 120 ),
		);
		$line = wp_json_encode( $row ) . "\n";
		$file = mvn_data_dir() . '/logs/security-' . gmdate( 'Ymd' ) . '.log';
		@file_put_contents( $file, $line, FILE_APPEND | LOCK_EX );

		$meta = get_option( self::OPTION, array() );
		if ( ! is_array( $meta ) ) {
			$meta = array();
		}
		$ring = isset( $meta['ring'] ) && is_array( $meta['ring'] ) ? $meta['ring'] : array();
		array_unshift( $ring, $row );
		$meta['ring']      = array_slice( $ring, 0, self::RING );
		$meta['last']      = $row;
		$meta['updated_at'] = gmdate( 'c' );
		update_option( self::OPTION, $meta, false );

		if ( class_exists( 'MVN_Audit_Log' ) && method_exists( 'MVN_Audit_Log', 'add' ) ) {
			MVN_Audit_Log::add( $action, array( 'target' => $target, 'result' => $result ) );
		}
	}

	/**
	 * @return array[]
	 */
	public static function recent( $limit = 40 ) {
		$meta = get_option( self::OPTION, array() );
		$ring = isset( $meta['ring'] ) && is_array( $meta['ring'] ) ? $meta['ring'] : array();
		return array_slice( $ring, 0, max( 1, (int) $limit ) );
	}
}
