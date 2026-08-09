<?php
/**
 * Updatable signature pack — bundled JSON + optional remote refresh.
 * Merges extra regex signatures and known-malware hashes with builtins.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Signature_Pack {

	const OPTION_META = 'mvn_sig_pack_meta';
	const STATE_FILE  = 'signature_pack';
	const MAX_BYTES   = 2097152;
	const MAX_SIGS    = 1000;
	const MAX_HASHES  = 10000;
	const MAX_PATTERN = 2048;

	/** @var array|null */
	private static $cache = null;

	/**
	 * Absolute path to active pack (mvn-data override or bundled).
	 */
	public static function active_path() {
		$local = self::local_path();
		if ( is_file( $local ) && is_readable( $local ) ) {
			return $local;
		}
		return self::bundled_path();
	}

	public static function bundled_path() {
		return MVN_PLUGIN_DIR . 'sources/signatures-pack.json';
	}

	public static function local_path() {
		return mvn_data_dir() . '/signatures/pack.json';
	}

	/**
	 * Remote URL for pack updates (empty = bundled-only until configured).
	 */
	public static function remote_url() {
		$url = defined( 'MVN_SIGNATURE_PACK_URL' ) ? MVN_SIGNATURE_PACK_URL : '';
		return (string) apply_filters( 'mvn_signature_pack_url', $url );
	}

	/**
	 * Load and decode pack JSON.
	 *
	 * @return array{version:string,updated_at:string,signatures:array,hashes:array}
	 */
	public static function load() {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		$path = self::active_path();
		$raw  = is_file( $path ) ? @file_get_contents( $path ) : false;
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( ! is_array( $data ) ) {
			self::$cache = array(
				'version'    => '0',
				'updated_at' => '',
				'signatures' => array(),
				'hashes'     => array(),
				'source'     => 'none',
			);
			return self::$cache;
		}

		$data['signatures'] = isset( $data['signatures'] ) && is_array( $data['signatures'] ) ? $data['signatures'] : array();
		$data['hashes']     = isset( $data['hashes'] ) && is_array( $data['hashes'] ) ? $data['hashes'] : array();
		$data['version']    = isset( $data['version'] ) ? (string) $data['version'] : '0';
		$data['updated_at'] = isset( $data['updated_at'] ) ? (string) $data['updated_at'] : '';
		$data['source']     = ( self::active_path() === self::local_path() ) ? 'local' : 'bundled';
		self::$cache        = $data;
		return self::$cache;
	}

	/**
	 * Clear static cache (after update).
	 */
	public static function flush_cache() {
		self::$cache = null;
	}

	/**
	 * Extra signatures from pack (validated).
	 */
	public static function extra_signatures() {
		$pack = self::load();
		$out  = array();
		foreach ( $pack['signatures'] as $sig ) {
			if ( empty( $sig['id'] ) || empty( $sig['pattern'] ) ) {
				continue;
			}
			if ( isset( $sig['enabled'] ) && ! $sig['enabled'] ) {
				continue;
			}
			if ( ! self::regex_is_safe( $sig['pattern'] ) ) {
				continue;
			}
			$out[] = array(
				'id'       => sanitize_key( $sig['id'] ),
				'label'    => isset( $sig['label'] ) ? (string) $sig['label'] : $sig['id'],
				'severity' => in_array( isset( $sig['severity'] ) ? $sig['severity'] : '', array( 'critical', 'warning', 'info' ), true )
					? $sig['severity']
					: 'warning',
				'pattern'  => (string) $sig['pattern'],
				'scope'    => isset( $sig['scope'] ) ? (string) $sig['scope'] : 'php',
				'clean'    => isset( $sig['clean'] ) ? (string) $sig['clean'] : 'none',
			);
		}
		return $out;
	}

	/**
	 * Enabled malware hashes keyed by algo:hash => meta.
	 */
	public static function hash_index() {
		$pack = self::load();
		$out  = array();
		foreach ( $pack['hashes'] as $row ) {
			if ( isset( $row['enabled'] ) && ! $row['enabled'] ) {
				continue;
			}
			$algo = isset( $row['algo'] ) ? strtolower( (string) $row['algo'] ) : 'sha256';
			$hash = isset( $row['hash'] ) ? strtolower( trim( (string) $row['hash'] ) ) : '';
			if ( ! $hash || ! in_array( $algo, array( 'md5', 'sha1', 'sha256' ), true ) ) {
				continue;
			}
			if ( ! preg_match( '/^[a-f0-9]+$/', $hash ) ) {
				continue;
			}
			$key         = $algo . ':' . $hash;
			$out[ $key ] = array(
				'algo'     => $algo,
				'hash'     => $hash,
				'label'    => isset( $row['label'] ) ? (string) $row['label'] : 'امضای هش شناخته‌شده',
				'severity' => in_array( isset( $row['severity'] ) ? $row['severity'] : '', array( 'critical', 'warning', 'info' ), true )
					? $row['severity']
					: 'critical',
			);
		}
		return $out;
	}

	/**
	 * Status for admin UI.
	 */
	public static function status() {
		$pack = self::load();
		$meta = get_option( self::OPTION_META, array() );
		return array(
			'version'       => $pack['version'],
			'updated_at'    => $pack['updated_at'],
			'source'        => $pack['source'],
			'sig_count'     => count( self::extra_signatures() ),
			'hash_count'    => count( self::hash_index() ),
			'remote_url'    => self::remote_url(),
			'has_remote'    => (bool) self::remote_url(),
			'last_check'    => isset( $meta['last_check'] ) ? (string) $meta['last_check'] : '',
			'last_ok'       => ! empty( $meta['last_ok'] ),
			'last_message'  => isset( $meta['last_message'] ) ? (string) $meta['last_message'] : '',
			'bundled_ver'   => self::bundled_version(),
		);
	}

	private static function bundled_version() {
		$path = self::bundled_path();
		if ( ! is_file( $path ) ) {
			return '0';
		}
		$raw  = @file_get_contents( $path );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		return ( is_array( $data ) && isset( $data['version'] ) ) ? (string) $data['version'] : '0';
	}

	/**
	 * Update pack from remote URL, or re-copy bundled if no remote.
	 *
	 * @return array|WP_Error Status array on success.
	 */
	public static function update() {
		$url = self::remote_url();
		if ( $url ) {
			if ( ! defined( 'MVN_SIGNATURE_PACK_PUBLIC_KEY' ) || ! MVN_SIGNATURE_PACK_PUBLIC_KEY ) {
				return new WP_Error( 'remote_disabled', 'به‌روزرسانی remote بدون MVN_SIGNATURE_PACK_PUBLIC_KEY غیرفعال است.' );
			}
			return self::install_from_url( $url );
		}
		return self::install_from_bundled();
	}

	/**
	 * Reset active pack to bundled copy.
	 */
	public static function install_from_bundled() {
		$src = self::bundled_path();
		if ( ! is_file( $src ) ) {
			return new WP_Error( 'no_bundled', 'فایل signatures-pack.json همراه پلاگین یافت نشد.' );
		}
		$raw = @file_get_contents( $src );
		if ( false === $raw ) {
			return new WP_Error( 'read_fail', 'خواندن بسته امضای همراه ناموفق بود.' );
		}
		return self::install_raw( $raw, 'bundled' );
	}

	public static function install_from_url( $url ) {
		$url = esc_url_raw( $url );
		if ( ! $url ) {
			return new WP_Error( 'bad_url', 'آدرس بسته امضا نامعتبر است.' );
		}
		if ( ! defined( 'MVN_SIGNATURE_PACK_PUBLIC_KEY' ) || ! MVN_SIGNATURE_PACK_PUBLIC_KEY ) {
			return new WP_Error( 'missing_public_key', 'کلید عمومی Ed25519 تنظیم نشده است.' );
		}
		if ( ! defined( 'MVN_SIGNATURE_PACK_HOST' ) || strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ) !== strtolower( MVN_SIGNATURE_PACK_HOST ) ) {
			return new WP_Error( 'host_not_pinned', 'Host بسته امضا با MVN_SIGNATURE_PACK_HOST pin نشده است.' );
		}
		$response = MVN_URL_Trust::get(
			$url,
			array(
				'timeout' => 60,
				'headers' => array( 'Accept' => 'application/json' ),
				'limit_response_size' => self::MAX_BYTES + 1,
			)
		);
		if ( is_wp_error( $response ) ) {
			self::save_meta( false, $response->get_error_message() );
			return new WP_Error( 'download_fail', 'دانلود بسته امضا ناموفق: ' . $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		if ( 200 !== (int) $code || '' === $body ) {
			self::save_meta( false, 'HTTP ' . $code );
			return new WP_Error( 'http_fail', 'پاسخ سرور بسته امضا نامعتبر بود (HTTP ' . $code . ').' );
		}
		if ( strlen( $body ) > self::MAX_BYTES ) {
			return new WP_Error( 'pack_too_large', 'حجم بسته امضا از سقف مجاز بیشتر است.' );
		}
		$sig_url = apply_filters( 'mvn_signature_pack_signature_url', $url . '.sig', $url );
		$sig_res = MVN_URL_Trust::get(
			$sig_url,
			array( 'timeout' => 30, 'limit_response_size' => 512, 'headers' => array( 'Accept' => 'text/plain' ) )
		);
		if ( is_wp_error( $sig_res ) || 200 !== (int) wp_remote_retrieve_response_code( $sig_res ) ) {
			return new WP_Error( 'signature_download_fail', 'دریافت detached signature ناموفق بود.' );
		}
		$verified = self::verify_ed25519( $body, trim( wp_remote_retrieve_body( $sig_res ) ) );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		return self::install_raw( $body, 'remote' );
	}

	/**
	 * Validate and write pack JSON into mvn-data/signatures/pack.json.
	 */
	private static function install_raw( $raw, $source ) {
		if ( ! is_string( $raw ) || strlen( $raw ) > self::MAX_BYTES ) {
			return new WP_Error( 'pack_too_large', 'حجم بسته امضا نامعتبر است.' );
		}
		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) || empty( $data['version'] ) ) {
			return new WP_Error( 'bad_json', 'ساختار JSON بسته امضا نامعتبر است.' );
		}
		if ( ! isset( $data['signatures'] ) || ! is_array( $data['signatures'] ) ) {
			$data['signatures'] = array();
		}
		if ( ! isset( $data['hashes'] ) || ! is_array( $data['hashes'] ) ) {
			$data['hashes'] = array();
		}
		if ( count( $data['signatures'] ) > self::MAX_SIGS || count( $data['hashes'] ) > self::MAX_HASHES ) {
			return new WP_Error( 'pack_limits', 'تعداد امضا/هش از سقف ایمنی عبور کرده است.' );
		}
		if ( ! empty( $data['min_plugin'] ) && version_compare( MVN_VERSION, $data['min_plugin'], '<' ) ) {
			return new WP_Error( 'plugin_too_old', 'این بسته به نسخه جدیدتر افزونه نیاز دارد.' );
		}
		if ( ! empty( $data['max_plugin'] ) && version_compare( MVN_VERSION, $data['max_plugin'], '>' ) ) {
			return new WP_Error( 'plugin_too_new', 'این بسته با نسخه فعلی افزونه سازگار نیست.' );
		}
		if ( 'remote' === $source ) {
			$current = self::load();
			if ( ! empty( $current['version'] ) && version_compare( (string) $data['version'], (string) $current['version'], '<' ) ) {
				return new WP_Error( 'rollback_blocked', 'نسخه قدیمی‌تر بسته امضا (anti-rollback) رد شد.' );
			}
		}

		// Soft-validate: at least one usable entry OR empty pack allowed for wipe.
		foreach ( $data['signatures'] as $sig ) {
			if ( empty( $sig['id'] ) || empty( $sig['pattern'] ) ) {
				continue;
			}
			if ( ! self::regex_is_safe( $sig['pattern'] ) ) {
				return new WP_Error( 'bad_regex', 'الگوی نامعتبر در امضا: ' . $sig['id'] );
			}
		}

		mvn_ensure_data_dirs();
		$dir = mvn_data_dir() . '/signatures';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			mvn_atomic_write( $dir . '/index.php', "<?php // Silence is golden.\n", 0644 );
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			mvn_atomic_write(
				$dir . '/.htaccess',
				"# BEGIN Mohtavanegar\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n# END Mohtavanegar\n",
				0644
			);
		}

		$json = wp_json_encode( $data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT );
		$ok   = mvn_atomic_write( self::local_path(), $json, 0600 );
		if ( ! $ok ) {
			return new WP_Error( 'write_fail', 'نوشتن بسته امضا در mvn-data ناموفق بود.' );
		}

		self::flush_cache();
		$msg = sprintf(
			'بسته امضا %s نصب شد (نسخه %s — %d امضا، %d هش).',
			$source,
			$data['version'],
			count( $data['signatures'] ),
			count( $data['hashes'] )
		);
		self::save_meta( true, $msg );
		mvn_log( 'Signature pack updated: ' . $msg );
		return self::status();
	}

	/**
	 * Reject costly/unbounded remote regexes before compilation.
	 *
	 * @param string $pattern PCRE pattern.
	 * @return bool
	 */
	public static function regex_is_safe( $pattern ) {
		if ( ! is_string( $pattern ) || '' === $pattern || strlen( $pattern ) > self::MAX_PATTERN ) {
			return false;
		}
		if ( preg_match( '/\([^)]*[+*][^)]*\)[+*{]/', $pattern )
			|| preg_match( '/(?:\.\*|\.\+){2,}/', $pattern )
			|| preg_match( '/\(\?(?:R|0|&|P>)/', $pattern )
			|| preg_match( '/\\\\[1-9][0-9]*/', $pattern ) ) {
			return false;
		}
		return false !== @preg_match( $pattern, str_repeat( 'a', 256 ) );
	}

	/**
	 * Verify a base64/hex detached Ed25519 signature.
	 *
	 * @param string $message Exact downloaded bytes.
	 * @param string $encoded Signature.
	 * @return true|WP_Error
	 */
	private static function verify_ed25519( $message, $encoded ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return new WP_Error( 'sodium_required', 'برای امضای Ed25519 افزونه sodium لازم است.' );
		}
		$key_raw = (string) MVN_SIGNATURE_PACK_PUBLIC_KEY;
		$key = ctype_xdigit( $key_raw ) ? @hex2bin( $key_raw ) : base64_decode( $key_raw, true );
		$sig = ctype_xdigit( $encoded ) ? @hex2bin( $encoded ) : base64_decode( $encoded, true );
		if ( ! is_string( $key ) || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $key )
			|| ! is_string( $sig ) || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return new WP_Error( 'bad_signature_format', 'فرمت کلید یا detached signature نامعتبر است.' );
		}
		return sodium_crypto_sign_verify_detached( $sig, $message, $key )
			? true
			: new WP_Error( 'signature_invalid', 'امضای Ed25519 بسته امضا معتبر نیست.' );
	}

	private static function save_meta( $ok, $message ) {
		update_option(
			self::OPTION_META,
			array(
				'last_check'    => gmdate( 'c' ),
				'last_ok'       => $ok ? 1 : 0,
				'last_message'  => $message,
			),
			false
		);
	}

	/**
	 * Match content against known malware hashes.
	 *
	 * @return array|null Hash meta or null.
	 */
	public static function match_hash( $content ) {
		$index = self::hash_index();
		if ( empty( $index ) ) {
			return null;
		}
		$digests = array(
			'md5'    => md5( $content ),
			'sha1'   => sha1( $content ),
			'sha256' => hash( 'sha256', $content ),
		);
		foreach ( $digests as $algo => $hash ) {
			$key = $algo . ':' . $hash;
			if ( isset( $index[ $key ] ) ) {
				return $index[ $key ];
			}
		}
		return null;
	}
}
