<?php
/**
 * Permissions fixer — set safe modes on files/dirs.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Permissions {

	const STATE_KEY = 'perms';
	const CHUNK     = 80;

	/**
	 * Start a permissions walk over ABSPATH (skipping mvn-data is fine — we still harden it).
	 */
	public static function start() {
		$files = mvn_list_files( ABSPATH, 250000 );
		// Also collect directories by walking parents of files.
		$dirs = array();
		foreach ( $files as $rel ) {
			$parts = explode( '/', $rel );
			$acc   = '';
			for ( $i = 0, $n = count( $parts ) - 1; $i < $n; $i++ ) {
				$acc          = $acc ? $acc . '/' . $parts[ $i ] : $parts[ $i ];
				$dirs[ $acc ] = true;
			}
		}
		$dirs[''] = true; // ABSPATH itself

		$items = array();
		foreach ( array_keys( $dirs ) as $d ) {
			$items[] = array( 'rel' => $d, 'type' => 'dir' );
		}
		foreach ( $files as $f ) {
			$items[] = array( 'rel' => $f, 'type' => 'file' );
		}

		$state = array(
			'status'     => 'running',
			'started_at' => gmdate( 'c' ),
			'total'      => count( $items ),
			'cursor'     => 0,
			'fixed'      => 0,
			'skipped'    => 0,
			'errors'     => array(),
			'items'      => $items,
		);
		mvn_state_write( self::STATE_KEY, $state );
		mvn_log( 'Permissions fix started: items=' . $state['total'] );
		return $state;
	}

	public static function tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) || 'running' !== $state['status'] ) {
			return $state;
		}

		$start = (int) $state['cursor'];
		$total = (int) $state['total'];
		$end   = min( $start + self::CHUNK, $total );
		$items = isset( $state['items'] ) ? $state['items'] : array();

		for ( $i = $start; $i < $end; $i++ ) {
			$item = $items[ $i ];
			$rel  = $item['rel'];
			$abs  = ( '' === $rel ) ? rtrim( ABSPATH, '/\\' ) : mvn_abs_path( $rel );
			if ( ! $abs || ! file_exists( $abs ) ) {
				$state['skipped']++;
				continue;
			}

			$target = ( 'dir' === $item['type'] ) ? 0755 : 0644;

			// wp-config.php should be tighter if possible.
			if ( 'wp-config.php' === $rel ) {
				$target = 0600;
			}

			$current = @fileperms( $abs );
			if ( false === $current ) {
				$state['skipped']++;
				continue;
			}
			$current_mode = $current & 0777;
			if ( $current_mode === $target ) {
				$state['skipped']++;
				continue;
			}

			if ( ! @chmod( $abs, $target ) ) {
				$state['errors'][] = $rel . ': chmod failed';
				continue;
			}
			$state['fixed']++;
		}

		$state['cursor']     = $end;
		$state['updated_at'] = gmdate( 'c' );

		if ( $end >= $total ) {
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
			$state['items']       = array();
			mvn_log( 'Permissions fix done: fixed=' . $state['fixed'] );
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function get_state() {
		return mvn_state_read( self::STATE_KEY );
	}
}
