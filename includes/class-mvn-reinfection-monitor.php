<?php
/**
 * Reinfection monitor — watch quarantined malware paths via WP-Cron (low overhead).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Reinfection_Monitor {

	const HOOK             = 'mvn_reinfection_watch';
	const OPTION           = 'mvn_watched_paths';
	const ENSURE_TRANSIENT = 'mvn_reinfection_ensured';

	public static function boot() {
		add_action( self::HOOK, array( __CLASS__, 'tick' ) );
		// Avoid wp_next_scheduled on every public request.
		if ( ( is_admin() && ! wp_doing_ajax() ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			add_action( 'init', array( __CLASS__, 'ensure' ), 25 );
		}
	}

	public static function ensure() {
		$list = self::watched();
		if ( empty( $list ) ) {
			// Nothing to watch — do not keep a recurring event.
			wp_clear_scheduled_hook( self::HOOK );
			return;
		}
		if ( get_transient( self::ENSURE_TRANSIENT ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + 600, 'hourly', self::HOOK );
		}
		set_transient( self::ENSURE_TRANSIENT, 1, 6 * HOUR_IN_SECONDS );
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::HOOK );
		delete_transient( self::ENSURE_TRANSIENT );
	}

	/**
	 * Watch a path after quarantine.
	 *
	 * @param string $rel      Relative path.
	 * @param string $issue_id Related finding id.
	 */
	public static function watch( $rel, $issue_id = '' ) {
		$rel  = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$list = get_option( self::OPTION, array() );
		if ( ! is_array( $list ) ) {
			$list = array();
		}
		$list[ $rel ] = array(
			'issue_id'   => (string) $issue_id,
			'watched_at' => gmdate( 'c' ),
			'hits'       => isset( $list[ $rel ]['hits'] ) ? (int) $list[ $rel ]['hits'] : 0,
		);
		update_option( self::OPTION, $list, false );
		if ( class_exists( 'MVN_File_Hash_Store' ) ) {
			MVN_File_Hash_Store::mark_status( $rel, 'watched' );
		}
		delete_transient( self::ENSURE_TRANSIENT );
		self::ensure();
		if ( class_exists( 'MVN_Security_Log' ) ) {
			MVN_Security_Log::write( 'watch_path', $rel, 'ok' );
		}
	}

	public static function unwatch( $rel ) {
		$rel  = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$list = get_option( self::OPTION, array() );
		if ( isset( $list[ $rel ] ) ) {
			unset( $list[ $rel ] );
			update_option( self::OPTION, $list, false );
		}
		if ( empty( $list ) ) {
			wp_clear_scheduled_hook( self::HOOK );
		}
	}

	/**
	 * @return array<string,array>
	 */
	public static function watched() {
		$list = get_option( self::OPTION, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * Periodic check — if path reappears, flag reinfection (do not blind-delete).
	 */
	public static function tick() {
		$list = self::watched();
		if ( empty( $list ) ) {
			wp_clear_scheduled_hook( self::HOOK );
			return;
		}
		foreach ( $list as $rel => $meta ) {
			$abs = mvn_abs_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			$list[ $rel ]['hits']     = isset( $meta['hits'] ) ? ( (int) $meta['hits'] + 1 ) : 1;
			$list[ $rel ]['last_hit'] = gmdate( 'c' );
			if ( class_exists( 'MVN_Security_Log' ) ) {
				MVN_Security_Log::write( 'reinfection_detected', $rel, 'alert' );
			}

			$correlated = class_exists( 'MVN_Persistence_Scanner' )
				? MVN_Persistence_Scanner::correlate_for_path( $rel, (int) @filemtime( $abs ) )
				: array();
			$issue      = array(
				'id'          => md5( $rel . '|reinfection_detected' ),
				'rel'         => $rel,
				'sig'         => 'reinfection_detected',
				'label'       => 'REINFECTION DETECTED',
				'severity'    => 'critical',
				'detail'      => 'Malware re-created after remediation. Possible persistence mechanism detected.',
				'action'      => 'quarantine',
				'confidence'  => 99,
				'source'      => 'persistence',
				'persistence' => $correlated,
			);
			$issues = MVN_Incidents::issues();
			$found  = false;
			foreach ( $issues as $i => $row ) {
				if ( isset( $row['id'] ) && $row['id'] === $issue['id'] ) {
					$issues[ $i ] = array_merge( $row, $issue );
					$found        = true;
					break;
				}
			}
			if ( ! $found ) {
				$issues[] = $issue;
			}
			MVN_Incidents::store_issues( $issues );
			MVN_Incidents::sync_scan( array( $issue ), 'reinfection-watch' );
		}
		update_option( self::OPTION, $list, false );
	}
}
