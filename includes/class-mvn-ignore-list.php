<?php
/**
 * User-marked safe / ignored findings.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Ignore_List {

	const OPTION = 'mvn_ignored_issues';

	public static function all() {
		$items = get_option( self::OPTION, array() );
		return is_array( $items ) ? $items : array();
	}

	/**
	 * Is this finding ignored for the current file state?
	 */
	public static function is_ignored( $rel, $sig, $file_hash = '' ) {
		$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
		$sig = sanitize_key( $sig );
		foreach ( self::all() as $item ) {
			if ( empty( $item['rel'] ) || empty( $item['sig'] ) ) {
				continue;
			}
			if ( $item['rel'] !== $rel || $item['sig'] !== $sig ) {
				continue;
			}
			// Permanent ignore (no hash) or hash still matches.
			if ( empty( $item['file_hash'] ) ) {
				return true;
			}
			if ( $file_hash && $item['file_hash'] === $file_hash ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Mark rel+sig as safe. Returns item id.
	 */
	public static function add( $rel, $sig, $file_hash = '', $permanent = false ) {
		$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
		$sig = sanitize_key( $sig );
		$id  = md5( $rel . '|' . $sig );

		$items = self::all();
		foreach ( $items as $item ) {
			if ( isset( $item['id'] ) && $item['id'] === $id ) {
				return $id;
			}
		}

		$items[] = array(
			'id'         => $id,
			'rel'        => $rel,
			'sig'        => $sig,
			'file_hash'  => $permanent ? '' : (string) $file_hash,
			'permanent'  => $permanent ? 1 : 0,
			'created_at' => gmdate( 'c' ),
			'created_by' => get_current_user_id(),
		);
		update_option( self::OPTION, $items, false );
		mvn_log( "Ignored finding: {$rel} [{$sig}]" );
		return $id;
	}

	public static function remove( $id ) {
		$id    = sanitize_text_field( $id );
		$items = self::all();
		$kept  = array();
		$found = false;
		foreach ( $items as $item ) {
			if ( isset( $item['id'] ) && $item['id'] === $id ) {
				$found = true;
				continue;
			}
			$kept[] = $item;
		}
		if ( $found ) {
			update_option( self::OPTION, $kept, false );
		}
		return $found;
	}

	public static function count() {
		return count( self::all() );
	}
}
