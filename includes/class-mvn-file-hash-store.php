<?php
/**
 * SHA256 file hash store for change / reinfection tracking.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_File_Hash_Store {

	const STATE_KEY = 'file_hashes';
	const MAX_ENTRIES = 8000;

	/**
	 * @return array<string,array>
	 */
	public static function all() {
		$data = mvn_state_read( self::STATE_KEY, array() );
		return is_array( $data ) ? $data : array();
	}

	/**
	 * Record or update a file snapshot.
	 *
	 * @param string $rel Relative path.
	 * @param array  $extra Optional: risk_score, status, sig.
	 * @return array|false Row or false.
	 */
	public static function touch( $rel, $extra = array() ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) ) {
			return false;
		}
		$hash = @hash_file( 'sha256', $abs );
		if ( ! $hash ) {
			return false;
		}
		$all  = self::all();
		$now  = gmdate( 'c' );
		$prev = isset( $all[ $rel ] ) ? $all[ $rel ] : null;
		$row  = array(
			'path'       => $rel,
			'hash'       => $hash,
			'size'       => (int) @filesize( $abs ),
			'mtime'      => (int) @filemtime( $abs ),
			'first_seen' => $prev && ! empty( $prev['first_seen'] ) ? $prev['first_seen'] : $now,
			'last_seen'  => $now,
			'status'     => isset( $extra['status'] ) ? (string) $extra['status'] : ( $prev && isset( $prev['status'] ) ? $prev['status'] : 'seen' ),
			'risk_score' => isset( $extra['risk_score'] ) ? (int) $extra['risk_score'] : ( $prev && isset( $prev['risk_score'] ) ? (int) $prev['risk_score'] : 0 ),
		);
		if ( $prev && ! empty( $prev['hash'] ) && $prev['hash'] !== $hash ) {
			$row['changed_at'] = $now;
			$row['prev_hash']  = $prev['hash'];
		}
		$all[ $rel ] = $row;
		if ( count( $all ) > self::MAX_ENTRIES ) {
			uasort(
				$all,
				static function ( $a, $b ) {
					return strcmp( isset( $a['last_seen'] ) ? $a['last_seen'] : '', isset( $b['last_seen'] ) ? $b['last_seen'] : '' );
				}
			);
			$all = array_slice( $all, -self::MAX_ENTRIES, null, true );
		}
		mvn_state_write( self::STATE_KEY, $all );
		return $row;
	}

	/**
	 * Mark a path as quarantined / watched for reinfection.
	 */
	public static function mark_status( $rel, $status, $risk = null ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$all = self::all();
		if ( empty( $all[ $rel ] ) ) {
			$all[ $rel ] = array(
				'path'       => $rel,
				'hash'       => '',
				'size'       => 0,
				'mtime'      => 0,
				'first_seen' => gmdate( 'c' ),
				'last_seen'  => gmdate( 'c' ),
			);
		}
		$all[ $rel ]['status']    = (string) $status;
		$all[ $rel ]['last_seen'] = gmdate( 'c' );
		if ( null !== $risk ) {
			$all[ $rel ]['risk_score'] = (int) $risk;
		}
		mvn_state_write( self::STATE_KEY, $all );
	}

	/**
	 * Files modified within ±$window_sec of $around_ts (unix).
	 *
	 * @return array[]
	 */
	public static function changed_near( $around_ts, $window_sec = 300 ) {
		$around_ts  = (int) $around_ts;
		$window_sec = max( 30, (int) $window_sec );
		$out        = array();
		foreach ( self::all() as $row ) {
			$mtime = isset( $row['mtime'] ) ? (int) $row['mtime'] : 0;
			if ( $mtime && abs( $mtime - $around_ts ) <= $window_sec ) {
				$out[] = $row;
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return ( isset( $b['risk_score'] ) ? (int) $b['risk_score'] : 0 ) - ( isset( $a['risk_score'] ) ? (int) $a['risk_score'] : 0 );
			}
		);
		return $out;
	}
}
