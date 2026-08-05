<?php
/**
 * Incremental scan index — mtime/size + clean flag per file.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_File_Index {

	const STATE_KEY = 'file_index';

	/** @var array Buffer written in batches during scan. */
	private static $buffer = array();

	public static function get_all() {
		$data = mvn_state_read( self::STATE_KEY, array() );
		return is_array( $data ) ? $data : array();
	}

	public static function get_entry( $rel ) {
		$rel = self::norm( $rel );
		$all = self::get_all();
		return isset( $all[ $rel ] ) ? $all[ $rel ] : null;
	}

	/**
	 * Can we skip deep scan for this file?
	 */
	public static function is_unchanged_clean( $rel, $mtime, $size ) {
		$entry = self::get_entry( $rel );
		if ( ! $entry || empty( $entry['clean'] ) ) {
			return false;
		}
		return (int) $entry['mtime'] === (int) $mtime && (int) $entry['size'] === (int) $size;
	}

	/**
	 * Queue an index update (flushed in batches).
	 */
	public static function mark( $rel, $clean, $mtime, $size ) {
		$rel = self::norm( $rel );
		self::$buffer[ $rel ] = array(
			'mtime'   => (int) $mtime,
			'size'    => (int) $size,
			'clean'   => $clean ? 1 : 0,
			'updated' => gmdate( 'c' ),
		);
	}

	public static function flush() {
		if ( empty( self::$buffer ) ) {
			return;
		}
		$all = self::get_all();
		foreach ( self::$buffer as $rel => $entry ) {
			$all[ $rel ] = $entry;
		}
		mvn_state_write( self::STATE_KEY, $all );
		self::$buffer = array();
	}

	/**
	 * Remove index entries for files no longer in the scanned set.
	 */
	public static function prune( $valid_paths ) {
		$valid = array();
		foreach ( $valid_paths as $rel ) {
			$valid[ self::norm( $rel ) ] = true;
		}
		$all = self::get_all();
		$changed = false;
		foreach ( array_keys( $all ) as $rel ) {
			if ( ! isset( $valid[ $rel ] ) ) {
				unset( $all[ $rel ] );
				$changed = true;
			}
		}
		if ( $changed ) {
			mvn_state_write( self::STATE_KEY, $all );
		}
	}

	public static function stats() {
		$all   = self::get_all();
		$clean = 0;
		foreach ( $all as $entry ) {
			if ( ! empty( $entry['clean'] ) ) {
				$clean++;
			}
		}
		return array(
			'total' => count( $all ),
			'clean' => $clean,
		);
	}

	public static function clear() {
		mvn_state_delete( self::STATE_KEY );
		self::$buffer = array();
	}

	private static function norm( $rel ) {
		return trim( str_replace( '\\', '/', (string) $rel ), '/' );
	}
}
