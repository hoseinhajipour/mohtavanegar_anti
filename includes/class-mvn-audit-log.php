<?php
/**
 * Structured, hash-chained JSONL audit log with rotation.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Audit_Log {

	const MAX_BYTES = 10485760;

	public static function record( $action, $before = '', $after = '', $result = 'ok', $context = array() ) {
		mvn_ensure_data_dirs();
		$file = mvn_data_dir() . '/logs/audit-' . gmdate( 'Y-m' ) . '.jsonl';
		if ( is_file( $file ) && filesize( $file ) >= self::MAX_BYTES ) {
			$file = mvn_data_dir() . '/logs/audit-' . gmdate( 'Y-m-d-His' ) . '.jsonl';
		}
		$state = mvn_state_read( 'audit_chain', array( 'last_hash' => str_repeat( '0', 64 ) ) );
		$user  = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$ip    = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$row   = array(
			'at' => gmdate( 'c' ),
			'actor' => $user && $user->exists() ? (int) $user->ID : 0,
			'ip_hash' => hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ),
			'action' => sanitize_key( $action ),
			'before_hash' => self::digest( $before ),
			'after_hash' => self::digest( $after ),
			'result' => (string) $result,
			'context' => self::redact( $context ),
			'prev_hash' => $state['last_hash'],
		);
		$row['hash'] = hash( 'sha256', wp_json_encode( $row ) );
		$line = wp_json_encode( $row, JSON_UNESCAPED_UNICODE ) . "\n";
		$fh = @fopen( $file, 'ab' );
		if ( ! $fh ) {
			return false;
		}
		@flock( $fh, LOCK_EX );
		$ok = false !== @fwrite( $fh, $line );
		@fflush( $fh );
		@flock( $fh, LOCK_UN );
		@fclose( $fh );
		if ( $ok ) {
			$state['last_hash'] = $row['hash'];
			mvn_state_write( 'audit_chain', $state );
		}
		self::rotate();
		return $ok;
	}

	private static function digest( $value ) {
		return hash( 'sha256', is_string( $value ) ? $value : wp_json_encode( $value ) );
	}

	private static function redact( $context ) {
		$out = array();
		foreach ( (array) $context as $key => $value ) {
			if ( preg_match( '/pass|token|secret|key|content|payload/i', (string) $key ) ) {
				$out[ $key ] = '[redacted]';
			} elseif ( is_scalar( $value ) || null === $value ) {
				$out[ $key ] = $value;
			}
		}
		return $out;
	}

	private static function rotate() {
		$cutoff = strtotime( '-180 days' );
		foreach ( glob( mvn_data_dir() . '/logs/audit-*.jsonl' ) ?: array() as $file ) {
			if ( filemtime( $file ) < $cutoff ) {
				@unlink( $file );
			}
		}
	}

	public static function read_recent( $limit = 200 ) {
		$rows  = array();
		$files = glob( mvn_data_dir() . '/logs/audit-*.jsonl' ) ?: array();
		rsort( $files );
		foreach ( $files as $file ) {
			$fh = @fopen( $file, 'rb' );
			if ( ! $fh ) {
				continue;
			}
			while ( ! feof( $fh ) && count( $rows ) < $limit ) {
				$row = json_decode( (string) fgets( $fh ), true );
				if ( is_array( $row ) ) {
					$rows[] = $row;
				}
			}
			fclose( $fh );
			if ( count( $rows ) >= $limit ) {
				break;
			}
		}
		return array_slice( $rows, -$limit );
	}
}
