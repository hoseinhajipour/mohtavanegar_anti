<?php
/**
 * Quarantine store — copies infected files before fix/delete.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Quarantine {

	const KEY_OPTION = 'mvn_quarantine_key';

	/**
	 * Site-local encryption key (not autoloaded).
	 *
	 * @return string|false Raw 32-byte key.
	 */
	private static function encryption_key() {
		$encoded = get_option( self::KEY_OPTION, '' );
		if ( is_string( $encoded ) && '' !== $encoded ) {
			$key = base64_decode( $encoded, true );
			if ( is_string( $key ) && 32 === strlen( $key ) ) {
				return $key;
			}
		}
		try {
			$key = random_bytes( 32 );
		} catch ( Exception $e ) {
			return false;
		}
		if ( ! add_option( self::KEY_OPTION, base64_encode( $key ), '', false ) ) {
			update_option( self::KEY_OPTION, base64_encode( $key ), false );
		}
		return $key;
	}

	/**
	 * Authenticated encryption for quarantine payloads.
	 *
	 * @param string $content Plain bytes.
	 * @return array{file:string,data:string,encrypted:int}|false
	 */
	private static function encrypt_payload( $content ) {
		$key = self::encryption_key();
		if ( false === $key ) {
			return false;
		}
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$blob  = 'MVNQ1' . $nonce . sodium_crypto_secretbox( $content, $nonce, $key );
			return array( 'file' => 'payload.enc', 'data' => $blob, 'encrypted' => 1 );
		}
		if ( function_exists( 'openssl_encrypt' ) ) {
			$iv  = random_bytes( 12 );
			$tag = '';
			$ct  = openssl_encrypt( $content, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			if ( false !== $ct ) {
				return array( 'file' => 'payload.enc', 'data' => 'MVNQ2' . $iv . $tag . $ct, 'encrypted' => 1 );
			}
		}
		return false;
	}

	/**
	 * Read and decrypt an entry payload (legacy payload.bin supported).
	 *
	 * @param string $dir  Entry directory.
	 * @param array  $meta Metadata.
	 * @return string|false
	 */
	private static function read_payload( $dir, $meta ) {
		$file = ! empty( $meta['payload_file'] ) ? basename( $meta['payload_file'] ) : 'payload.bin';
		$blob = @file_get_contents( $dir . '/' . $file );
		if ( false === $blob ) {
			return false;
		}
		if ( empty( $meta['encrypted'] ) ) {
			return $blob;
		}
		$key = self::encryption_key();
		if ( false === $key ) {
			return false;
		}
		$magic = substr( $blob, 0, 5 );
		if ( 'MVNQ1' === $magic && function_exists( 'sodium_crypto_secretbox_open' ) ) {
			$nlen  = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
			$nonce = substr( $blob, 5, $nlen );
			return sodium_crypto_secretbox_open( substr( $blob, 5 + $nlen ), $nonce, $key );
		}
		if ( 'MVNQ2' === $magic && function_exists( 'openssl_decrypt' ) ) {
			$iv  = substr( $blob, 5, 12 );
			$tag = substr( $blob, 17, 16 );
			return openssl_decrypt( substr( $blob, 33 ), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
		}
		return false;
	}

	/**
	 * Fast restore safety check.
	 *
	 * @param string $content Payload.
	 * @param string $rel     Original path.
	 * @return WP_Error|true
	 */
	private static function payload_restore_safe( $content, $rel ) {
		if ( class_exists( 'MVN_Signature_Pack' ) && MVN_Signature_Pack::match_hash( $content ) ) {
			return new WP_Error( 'known_malware', 'بازیابی مسدود شد: payload با هش بدافزار شناخته‌شده تطابق دارد.' );
		}
		foreach ( function_exists( 'mvn_signatures' ) ? mvn_signatures() : array() as $sig ) {
			if ( empty( $sig['pattern'] ) || 'critical' !== ( isset( $sig['severity'] ) ? $sig['severity'] : '' ) ) {
				continue;
			}
			if ( @preg_match( $sig['pattern'], $content ) ) {
				return new WP_Error(
					'malware_signature',
					'بازیابی مسدود شد: امضای بحرانی «' . ( isset( $sig['label'] ) ? $sig['label'] : $sig['id'] ) . '» در payload وجود دارد.'
				);
			}
		}
		if ( preg_match( '#(?:^|/)uploads/.*\.(?:php\d*|phtml|pht|inc)$#i', str_replace( '\\', '/', $rel ) ) ) {
			return new WP_Error( 'php_upload_restore', 'بازیابی PHP داخل uploads بدون تأیید اجباری مجاز نیست.' );
		}
		return true;
	}

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

		$protected = self::encrypt_payload( $content );
		if ( false === $protected ) {
			$protected = array( 'file' => 'payload.bin', 'data' => $content, 'encrypted' => 0 );
		}
		$saved = mvn_atomic_write( $dir . '/' . $protected['file'], $protected['data'], 0600 );
		if ( false === $saved ) {
			return false;
		}

		$record = array_merge(
			array(
				'id'         => $id,
				'rel'        => $rel,
				'size'       => strlen( $content ),
				'hash'       => md5( $content ),
				'sha256'     => hash( 'sha256', $content ),
				'created_at' => gmdate( 'c' ),
				'reason'     => isset( $meta['reason'] ) ? $meta['reason'] : 'infected',
				'payload_file' => $protected['file'],
				'encrypted'  => $protected['encrypted'],
			),
			$meta
		);
		mvn_atomic_write( $dir . '/meta.json', wp_json_encode( $record ), 0600 );
		mvn_log( "Quarantined: {$rel} -> {$id}" );
		self::rotate();
		return $id;
	}

	/**
	 * Enforce quarantine age, entry-count and total-size retention.
	 */
	public static function rotate() {
		$root       = mvn_data_dir() . '/quarantine';
		$max_age    = (int) apply_filters( 'mvn_quarantine_retention_days', 30 ) * DAY_IN_SECONDS;
		$max_count  = (int) apply_filters( 'mvn_quarantine_max_entries', 500 );
		$max_bytes  = (int) apply_filters( 'mvn_quarantine_max_bytes', 512 * MB_IN_BYTES );
		$entries    = array();
		$total_size = 0;
		foreach ( glob( $root . '/*', GLOB_ONLYDIR ) ?: array() as $dir ) {
			$size = 0;
			foreach ( glob( $dir . '/*' ) ?: array() as $file ) {
				$size += is_file( $file ) ? (int) filesize( $file ) : 0;
			}
			$mtime = (int) @filemtime( $dir );
			$entries[] = array( 'id' => basename( $dir ), 'mtime' => $mtime, 'size' => $size );
			$total_size += $size;
		}
		usort(
			$entries,
			static function ( $a, $b ) {
				return $a['mtime'] <=> $b['mtime'];
			}
		);
		foreach ( $entries as $index => $entry ) {
			$expired = $max_age > 0 && $entry['mtime'] < time() - $max_age;
			$over    = count( $entries ) - $index > $max_count || $total_size > $max_bytes;
			if ( $expired || $over ) {
				self::purge( $entry['id'] );
				$total_size -= $entry['size'];
			}
		}
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
	 *
	 * @param string $id    Quarantine ID.
	 * @param bool   $force Explicit second-confirmation override.
	 */
	public static function restore( $id, $force = false ) {
		$id  = preg_replace( '/[^a-zA-Z0-9\-]/', '', $id );
		$dir = mvn_data_dir() . '/quarantine/' . $id;
		if ( ! is_dir( $dir ) ) {
			return new WP_Error( 'not_found', 'یافت نشد.' );
		}
		$meta = json_decode( (string) @file_get_contents( $dir . '/meta.json' ), true );
		if ( empty( $meta['rel'] ) ) {
			return new WP_Error( 'bad_meta', 'متادیتا نامعتبر.' );
		}
		if ( 0 === strpos( (string) $meta['rel'], 'db:' ) ) {
			return new WP_Error( 'db_restore_required', 'این ورودی snapshot دیتابیس است و نباید به‌صورت فایل بازیابی شود.' );
		}
		$abs = mvn_abs_path( $meta['rel'] );
		if ( ! $abs || false === mvn_safe_write_path( $abs ) ) {
			return new WP_Error( 'bad_path', 'مسیر نامعتبر.' );
		}
		$parent = dirname( $abs );
		if ( ! is_dir( $parent ) ) {
			wp_mkdir_p( $parent );
		}
		$payload = self::read_payload( $dir, $meta );
		if ( false === $payload ) {
			return new WP_Error( 'no_payload', 'محتوای قرنطینه پیدا نشد.' );
		}
		if ( ! $force ) {
			$safe = self::payload_restore_safe( $payload, $meta['rel'] );
			if ( is_wp_error( $safe ) ) {
				return $safe;
			}
		}
		if ( is_file( $abs ) ) {
			self::store( $meta['rel'], array( 'reason' => 'pre-restore-snapshot', 'restoring_id' => $id ) );
		}
		$ok = mvn_atomic_write( $abs, $payload, 0644 );
		if ( false === $ok ) {
			return new WP_Error( 'write_fail', 'نوشتن فایل ناموفق بود.' );
		}
		mvn_invalidate_runtime_caches( array( $abs ) );
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
		foreach ( array( 'payload.bin', 'payload.enc', 'meta.json' ) as $f ) {
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
