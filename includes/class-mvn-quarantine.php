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
		$content = @file_get_contents( $abs );
		if ( false === $content ) {
			return false;
		}
		return self::store_text( $rel, $content, $meta );
	}

	/**
	 * Isolate malware: quarantine copy then remove the live file (move semantics).
	 *
	 * @param string $rel  Relative path.
	 * @param array  $meta Extra metadata.
	 * @return string|WP_Error Quarantine id on success.
	 */
	public static function isolate( $rel, $meta = array() ) {
		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) ) {
			return true; // already gone
		}
		$meta['isolated'] = 1;
		$id = self::store( $rel, $meta );
		if ( ! $id ) {
			return new WP_Error( 'quarantine_fail', 'قرنطینه قبل از ایزوله کردن ناموفق بود.' );
		}
		if ( ! @unlink( $abs ) ) {
			return new WP_Error( 'unlink_fail', 'فایل قرنطینه شد ولی حذف از مسیر اصلی ناموفق بود (سطح دسترسی؟).' );
		}
		mvn_log( "Isolated (moved to quarantine): {$rel} -> {$id}" );
		return $id;
	}

	/**
	 * Store arbitrary text/binary payload (e.g. DB row backup).
	 *
	 * @param string $rel     Logical path label.
	 * @param string $content Payload bytes.
	 * @param array  $meta    Extra metadata.
	 * @return string|false Quarantine id.
	 */
	public static function store_text( $rel, $content, $meta = array() ) {
		if ( ! is_string( $content ) ) {
			return false;
		}
		mvn_ensure_data_dirs();
		$id  = gmdate( 'Ymd-His' ) . '-' . substr( md5( $rel . microtime( true ) ), 0, 8 );
		$dir = mvn_data_dir() . '/quarantine/' . $id;
		wp_mkdir_p( $dir );

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

	/**
	 * Batch restore or purge quarantine entries.
	 *
	 * @param string[] $ids    Quarantine IDs.
	 * @param string   $action restore|purge
	 * @param int      $limit  Max items per call.
	 * @return array {done, failed, errors, remaining, remaining_ids}
	 */
	public static function batch( $ids, $action, $limit = 15 ) {
		if ( ! in_array( $action, array( 'restore', 'purge' ), true ) ) {
			return array(
				'done'           => 0,
				'failed'         => 0,
				'errors'         => array( 'عمل نامعتبر.' ),
				'remaining'      => is_array( $ids ) ? count( $ids ) : 0,
				'remaining_ids'  => is_array( $ids ) ? $ids : array(),
			);
		}

		$clean = array();
		foreach ( (array) $ids as $id ) {
			$id = preg_replace( '/[^a-zA-Z0-9\-]/', '', sanitize_text_field( $id ) );
			if ( $id ) {
				$clean[] = $id;
			}
		}
		$clean = array_values( array_unique( $clean ) );

		$chunk      = array_slice( $clean, 0, $limit );
		$rest       = array_slice( $clean, $limit );
		$done       = 0;
		$failed     = 0;
		$errors     = array();
		$failed_ids = array();

		foreach ( $chunk as $id ) {
			if ( 'restore' === $action ) {
				$r = self::restore( $id );
				if ( is_wp_error( $r ) ) {
					$failed++;
					$failed_ids[] = $id;
					$errors[]     = $id . ': ' . $r->get_error_message();
				} else {
					$done++;
				}
			} elseif ( self::purge( $id ) ) {
				$done++;
			} else {
				$failed++;
				$failed_ids[] = $id;
				$errors[]     = $id . ': حذف ناموفق';
			}
		}

		$remaining_ids = array_merge( $failed_ids, $rest );

		return array(
			'done'          => $done,
			'failed'        => $failed,
			'errors'        => array_slice( $errors, 0, 10 ),
			'remaining'     => count( $remaining_ids ),
			'remaining_ids' => $remaining_ids,
		);
	}
}
