<?php
/**
 * Quarantine store — copies infected files before fix/delete.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Quarantine {

	/**
	 * Copy a site file into quarantine. Returns quarantine id or false.
	 *
	 * @param string $rel Relative path under ABSPATH.
	 * @param array  $meta Extra metadata (issues, reason, ...).
	 */
	public static function store( $rel, $meta = array() ) {
		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return false;
		}
		mvn_ensure_data_dirs();
		$id   = gmdate( 'Ymd-His' ) . '-' . substr( md5( $rel . microtime( true ) ), 0, 8 );
		$dir  = mvn_data_dir() . '/quarantine/' . $id;
		wp_mkdir_p( $dir );

		$content = @file_get_contents( $abs );
		if ( false === $content ) {
			return false;
		}
		$saved = @file_put_contents( $dir . '/payload.bin', $content );
		if ( false === $saved ) {
			return false;
		}

		$record = array_merge(
			array(
				'id'         => $id,
				'rel'        => $rel,
				'size'       => strlen( $content ),
				'hash'       => md5( $content ),
				'created_at' => gmdate( 'c' ),
				'reason'     => isset( $meta['reason'] ) ? $meta['reason'] : 'infected',
			),
			$meta
		);
		@file_put_contents( $dir . '/meta.json', wp_json_encode( $record ) );
		mvn_log( "Quarantined: {$rel} -> {$id}" );
		return $id;
	}

	/**
	 * List all quarantine entries, newest first.
	 */
	public static function list_all() {
		$dir = mvn_data_dir() . '/quarantine';
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$out = array();
		foreach ( scandir( $dir ) as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$meta = $dir . '/' . $item . '/meta.json';
			if ( ! is_file( $meta ) ) {
				continue;
			}
			$data = json_decode( (string) file_get_contents( $meta ), true );
			if ( is_array( $data ) ) {
				$out[] = $data;
			}
		}
		usort(
			$out,
			function ( $a, $b ) {
				return strcmp( isset( $b['created_at'] ) ? $b['created_at'] : '', isset( $a['created_at'] ) ? $a['created_at'] : '' );
			}
		);
		return $out;
	}

	/**
	 * Restore a quarantined file to its original relative path.
	 */
	public static function restore( $id ) {
		$id  = preg_replace( '/[^a-zA-Z0-9\-]/', '', $id );
		$dir = mvn_data_dir() . '/quarantine/' . $id;
		if ( ! is_dir( $dir ) ) {
			return new WP_Error( 'not_found', 'یافت نشد.' );
		}
		$meta = json_decode( (string) @file_get_contents( $dir . '/meta.json' ), true );
		if ( empty( $meta['rel'] ) ) {
			return new WP_Error( 'bad_meta', 'متادیتا نامعتبر.' );
		}
		$abs = mvn_abs_path( $meta['rel'] );
		if ( ! $abs ) {
			return new WP_Error( 'bad_path', 'مسیر نامعتبر.' );
		}
		$parent = dirname( $abs );
		if ( ! is_dir( $parent ) ) {
			wp_mkdir_p( $parent );
		}
		$payload = @file_get_contents( $dir . '/payload.bin' );
		if ( false === $payload ) {
			return new WP_Error( 'no_payload', 'محتوای قرنطینه پیدا نشد.' );
		}
		$ok = @file_put_contents( $abs, $payload );
		if ( false === $ok ) {
			return new WP_Error( 'write_fail', 'نوشتن فایل ناموفق بود.' );
		}
		mvn_log( "Restored from quarantine: {$meta['rel']} ({$id})" );
		return true;
	}

	/**
	 * Permanently delete a quarantine entry.
	 */
	public static function purge( $id ) {
		$id  = preg_replace( '/[^a-zA-Z0-9\-]/', '', $id );
		$dir = mvn_data_dir() . '/quarantine/' . $id;
		if ( ! is_dir( $dir ) ) {
			return false;
		}
		foreach ( array( 'payload.bin', 'meta.json' ) as $f ) {
			if ( file_exists( $dir . '/' . $f ) ) {
				@unlink( $dir . '/' . $f );
			}
		}
		@rmdir( $dir );
		mvn_log( "Purged quarantine: {$id}" );
		return true;
	}
}
