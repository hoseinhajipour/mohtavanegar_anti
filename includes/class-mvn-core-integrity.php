<?php
/**
 * WordPress core integrity — MD5 checksum verification.
 *
 * Compares wp-admin / wp-includes / root core files against wordpress.org API
 * (fallback: bundled wordpress_core.zip).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Core_Integrity {

	const STATE_KEY     = 'core_integrity';
	const CHECKSUMS_KEY = 'core_checksums';
	const CHUNK         = 50;

	/**
	 * Attach core checksum phase to an active scan job.
	 */
	public static function begin_phase( &$state ) {
		$checksums = self::load_checksums();
		if ( is_wp_error( $checksums ) ) {
			MVN_Scanner::add_finding(
				$state,
				array(
					'source'   => 'core',
					'rel'      => 'core:checksum-source',
					'sig'      => 'core_checksum_unavailable',
					'label'    => 'بررسی checksum هسته ممکن نشد',
					'severity' => 'warning',
					'detail'   => $checksums->get_error_message(),
					'action'   => 'core_repair',
					'snippet'  => '',
				),
				'',
				''
			);
			$state['phase']           = 'core';
			$state['core_sub']        = 'done';
			$state['core_cursor']     = 0;
			$state['core_total']      = 0;
			$state['core_processed']  = 0;
			$state['total']           = 0;
			$state['processed']       = 0;
			$state['cursor']          = 0;
			return;
		}

		mvn_state_write( self::CHECKSUMS_KEY, $checksums );

		$files  = array_keys( $checksums['files'] );
		sort( $files );

		$state['phase']          = 'core';
		$state['core_sub']       = 'verify';
		$state['core_source']    = $checksums['source'];
		$state['core_version']   = $checksums['version'];
		$state['core_locale']    = $checksums['locale'];
		$state['core_files']     = $files;
		$state['core_cursor']    = 0;
		$state['core_total']     = count( $files );
		$state['core_processed'] = 0;
		$state['core_extras']    = null;
		$state['file_total']     = isset( $state['file_total'] ) ? (int) $state['file_total'] : ( isset( $state['total'] ) ? (int) $state['total'] : 0 );
		$state['file_processed'] = isset( $state['file_processed'] ) ? (int) $state['file_processed'] : ( isset( $state['processed'] ) ? (int) $state['processed'] : 0 );
		$state['total']          = count( $files );
		$state['processed']      = 0;
		$state['cursor']         = 0;

		if ( ! isset( $state['stats']['core'] ) ) {
			$state['stats']['core'] = 0;
		}

		mvn_log( 'Core checksum phase started: ' . count( $files ) . ' files (source=' . $checksums['source'] . ', v=' . $checksums['version'] . ')' );
	}

	/**
	 * Process next chunk during scan or standalone job.
	 *
	 * @param array $state Scan state or standalone integrity state.
	 */
	public static function tick( &$state ) {
		if ( ! empty( $state['core_sub'] ) && 'done' === $state['core_sub'] ) {
			return;
		}

		$sub = isset( $state['core_sub'] ) ? $state['core_sub'] : 'verify';

		if ( 'verify' === $sub ) {
			self::tick_verify( $state );
			if ( self::verify_done( $state ) ) {
				self::begin_extras( $state );
			}
			return;
		}

		if ( 'extras' === $sub ) {
			self::tick_extras( $state );
		}
	}

	public static function is_done( $state ) {
		$sub = isset( $state['core_sub'] ) ? $state['core_sub'] : '';
		return 'done' === $sub || ( 'extras' === $sub && self::extras_done( $state ) );
	}

	public static function sub_phase_label() {
		return 'checksum هسته';
	}

	/**
	 * Standalone integrity check (repair page).
	 *
	 * @return array|WP_Error
	 */
	public static function standalone_start() {
		$state = array(
			'id'         => gmdate( 'YmdHis' ) . '-core',
			'mode'       => 'standalone',
			'status'     => 'running',
			'started_at' => gmdate( 'c' ),
			'issues'     => array(),
			'stats'      => array(
				'critical' => 0,
				'warning'  => 0,
				'core'     => 0,
			),
		);
		self::begin_phase( $state );
		if ( self::is_done( $state ) ) {
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
		}
		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function standalone_tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || 'running' !== $state['status'] ) {
			return $state;
		}

		self::tick( $state );
		$state['updated_at'] = gmdate( 'c' );

		if ( self::is_done( $state ) ) {
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
			$state['core_files']  = array();
			$state['core_extras'] = array();
			self::merge_standalone_issues( $state );
			mvn_state_delete( self::CHECKSUMS_KEY );
			mvn_log( 'Standalone core checksum done: issues=' . count( isset( $state['issues'] ) ? $state['issues'] : array() ) );
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function get_standalone_state() {
		return mvn_state_read( self::STATE_KEY );
	}

	/**
	 * Last standalone / scan core summary for dashboard.
	 */
	public static function last_summary() {
		$last = get_option( 'mvn_core_integrity_last', array() );
		return is_array( $last ) ? $last : array();
	}

	/* ===================== Internals ===================== */

	private static function load_checksums() {
		$cached = mvn_state_read( self::CHECKSUMS_KEY );
		if ( ! empty( $cached['files'] ) && is_array( $cached['files'] ) ) {
			return $cached;
		}

		$version = get_bloginfo( 'version' );
		$locale  = get_locale();
		$from_api = self::fetch_api_checksums( $version, $locale );
		if ( ! is_wp_error( $from_api ) ) {
			return $from_api;
		}

		$from_zip = self::checksums_from_zip();
		if ( ! is_wp_error( $from_zip ) ) {
			$from_zip['api_error'] = $from_api->get_error_message();
			return $from_zip;
		}

		return $from_api;
	}

	private static function fetch_api_checksums( $version, $locale ) {
		$transient_key = 'mvn_cksum_v2_' . md5( $version . '|' . $locale );
		$cached        = get_transient( $transient_key );
		if ( is_array( $cached ) && ! empty( $cached['files'] ) ) {
			return $cached;
		}

		$url      = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode( $version ) . '&locale=' . rawurlencode( $locale );
		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 20,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			if ( 'en_US' !== $locale ) {
				return self::fetch_api_checksums( $version, 'en_US' );
			}
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( 200 !== $code || empty( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) {
			if ( 'en_US' !== $locale ) {
				return self::fetch_api_checksums( $version, 'en_US' );
			}
			return new WP_Error( 'checksum_api', 'پاسخ API checksums وردپرس نامعتبر بود (HTTP ' . $code . ').' );
		}

		$out = array(
			'source'  => 'api',
			'version' => $version,
			'locale'  => $locale,
			'files'   => self::filter_core_only_checksums( $data['checksums'] ),
		);
		if ( empty( $out['files'] ) ) {
			return new WP_Error( 'checksum_empty', 'بعد از فیلتر هسته، هیچ checksum معتبری باقی نماند.' );
		}
		set_transient( $transient_key, $out, DAY_IN_SECONDS );
		return $out;
	}

	/**
	 * Keep only real WordPress core paths (exclude bundled themes/plugins from API list).
	 *
	 * wordpress.org checksums include default themes (twentytwenty*) and akismet —
	 * those are optional and must not be reported as "missing core files".
	 *
	 * @param array $files path => md5
	 * @return array
	 */
	private static function filter_core_only_checksums( $files ) {
		$out = array();
		if ( ! is_array( $files ) ) {
			return $out;
		}
		foreach ( $files as $rel => $hash ) {
			$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
			if ( ! $rel || ! is_string( $hash ) || '' === $hash ) {
				continue;
			}
			// Never treat wp-content as core integrity scope.
			if ( 0 === strpos( $rel, 'wp-content/' ) ) {
				continue;
			}
			if ( ! mvn_is_core_path( $rel ) ) {
				continue;
			}
			$out[ $rel ] = $hash;
		}
		return $out;
	}

	private static function checksums_from_zip() {
		if ( ! class_exists( 'ZipArchive' ) || ! is_file( MVN_SOURCE_ZIP ) ) {
			return new WP_Error( 'no_zip', 'آرشیو wordpress_core.zip برای fallback در دسترس نیست.' );
		}

		$zip = new ZipArchive();
		if ( true !== $zip->open( MVN_SOURCE_ZIP ) ) {
			return new WP_Error( 'zip_open', 'باز کردن wordpress_core.zip ناموفق بود.' );
		}

		$files = array();
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			if ( empty( $stat['name'] ) ) {
				continue;
			}
			$name = class_exists( 'MVN_Core_Repair' )
				? MVN_Core_Repair::strip_zip_root( $stat['name'] )
				: ltrim( str_replace( '\\', '/', $stat['name'] ), '/' );
			if ( '' === $name || '/' === substr( $name, -1 ) ) {
				continue;
			}
			if ( ! mvn_is_core_path( $name ) ) {
				continue;
			}
			$content = $zip->getFromIndex( $i );
			if ( false === $content ) {
				continue;
			}
			$files[ $name ] = md5( $content );
		}
		$zip->close();

		if ( empty( $files ) ) {
			return new WP_Error( 'zip_empty', 'هیچ فایل هسته‌ای در zip یافت نشد.' );
		}

		return array(
			'source'  => 'zip',
			'version' => get_bloginfo( 'version' ),
			'locale'  => 'zip-fallback',
			'files'   => $files,
		);
	}

	private static function tick_verify( &$state ) {
		$checksums = mvn_state_read( self::CHECKSUMS_KEY );
		if ( empty( $checksums['files'] ) ) {
			$state['core_sub'] = 'done';
			return;
		}

		$files  = isset( $state['core_files'] ) ? $state['core_files'] : array();
		$start  = (int) $state['core_cursor'];
		$end    = min( $start + self::CHUNK, count( $files ) );
		$map    = $checksums['files'];

		for ( $i = $start; $i < $end; $i++ ) {
			$rel = $files[ $i ];
			self::verify_one( $rel, isset( $map[ $rel ] ) ? $map[ $rel ] : '', $state, $checksums );
		}

		$state['core_cursor']    = $end;
		$state['core_processed'] = $end;
		$state['processed']      = $end;
		$state['cursor']         = $end;
	}

	private static function verify_one( $rel, $expected, &$state, $checksums ) {
		$abs = mvn_abs_path( $rel );
		if ( ! $expected ) {
			return;
		}

		if ( ! $abs || ! is_file( $abs ) ) {
			self::add_core_finding(
				$state,
				$rel,
				'core_checksum_missing',
				'فایل هسته گم‌شده',
				'critical',
				'فایل رسمی وردپرس روی دیسک وجود ندارد.',
				'',
				$expected,
				$checksums
			);
			return;
		}

		$hash = @md5_file( $abs );
		if ( ! $hash ) {
			return;
		}

		if ( strtolower( $hash ) !== strtolower( $expected ) ) {
			self::add_core_finding(
				$state,
				$rel,
				'core_checksum_modified',
				'فایل هسته تغییر یافته (checksum)',
				'critical',
				'MD5 محلی: ' . $hash . ' — مورد انتظار: ' . $expected,
				$hash,
				$expected,
				$checksums
			);
		}
	}

	private static function verify_done( $state ) {
		$files = isset( $state['core_files'] ) ? $state['core_files'] : array();
		return (int) $state['core_cursor'] >= count( $files );
	}

	private static function begin_extras( &$state ) {
		$checksums = mvn_state_read( self::CHECKSUMS_KEY );
		$known     = isset( $checksums['files'] ) ? array_keys( $checksums['files'] ) : array();
		$known_map = array_flip( $known );

		$local = array();
		foreach ( array( ABSPATH . 'wp-admin', ABSPATH . 'wp-includes' ) as $root ) {
			if ( is_dir( $root ) ) {
				foreach ( mvn_list_files_in( $root ) as $rel_in ) {
					$prefix = ( false !== strpos( $root, 'wp-admin' ) ) ? 'wp-admin/' : 'wp-includes/';
					$local[] = $prefix . ltrim( str_replace( '\\', '/', $rel_in ), '/' );
				}
			}
		}
		foreach ( mvn_core_root_files() as $root_file ) {
			if ( is_file( ABSPATH . $root_file ) ) {
				$local[] = $root_file;
			}
		}

		$extras = array();
		foreach ( $local as $rel ) {
			$rel = ltrim( str_replace( '\\', '/', $rel ), '/' );
			if ( ! isset( $known_map[ $rel ] ) ) {
				$extras[] = $rel;
			}
		}
		sort( $extras );

		$state['core_sub']       = 'extras';
		$state['core_extras']    = $extras;
		$state['core_cursor']    = 0;
		$state['core_total']     = count( $extras );
		$state['total']          = count( $extras );
		$state['processed']      = 0;
		$state['cursor']         = 0;
	}

	private static function tick_extras( &$state ) {
		$extras = isset( $state['core_extras'] ) ? $state['core_extras'] : array();
		$start  = (int) $state['core_cursor'];
		$end    = min( $start + self::CHUNK, count( $extras ) );
		$checksums = mvn_state_read( self::CHECKSUMS_KEY );

		for ( $i = $start; $i < $end; $i++ ) {
			$rel = $extras[ $i ];
			self::add_core_finding(
				$state,
				$rel,
				'core_checksum_extra',
				'فایل اضافی در پوشه هسته',
				'critical',
				'این فایل جزو هسته رسمی وردپرس نیست — احتمال backdoor.',
				is_file( mvn_abs_path( $rel ) ) ? @md5_file( mvn_abs_path( $rel ) ) : '',
				'',
				$checksums
			);
		}

		$state['core_cursor']    = $end;
		$state['core_processed'] = ( isset( $state['core_files'] ) ? count( $state['core_files'] ) : 0 ) + $end;
		$state['processed']      = $end;
		$state['cursor']         = $end;

		if ( $end >= count( $extras ) ) {
			$state['core_sub'] = 'done';
			mvn_state_delete( self::CHECKSUMS_KEY );
			self::save_last_summary( $state, $checksums );
		}
	}

	private static function extras_done( $state ) {
		$extras = isset( $state['core_extras'] ) ? $state['core_extras'] : array();
		return (int) $state['core_cursor'] >= count( $extras );
	}

	private static function add_core_finding( &$state, $rel, $sig, $label, $severity, $detail, $actual, $expected, $checksums ) {
		$snippet = '';
		$abs     = mvn_abs_path( $rel );
		if ( $abs && is_file( $abs ) && is_readable( $abs ) && filesize( $abs ) < 50000 ) {
			$raw = @file_get_contents( $abs, false, null, 0, 200 );
			if ( is_string( $raw ) ) {
				$snippet = preg_replace( '/\s+/', ' ', $raw );
				$snippet = function_exists( 'mb_substr' ) ? mb_substr( $snippet, 0, 180 ) : substr( $snippet, 0, 180 );
			}
		}

		$source_label = isset( $checksums['source'] ) ? $checksums['source'] : 'unknown';
		$version      = isset( $checksums['version'] ) ? $checksums['version'] : '';

		// Extras → quarantine+delete; modified/missing → selective zip restore.
		$action = 'core_repair_file';
		if ( 'core_checksum_extra' === $sig ) {
			$action = 'delete_core_extra';
		} elseif ( 'core_checksum_unavailable' === $sig ) {
			$action = 'core_repair';
		}

		$added = MVN_Scanner::add_finding(
			$state,
			array(
				'source'        => 'core',
				'rel'           => $rel,
				'sig'           => $sig,
				'label'         => $label,
				'severity'      => $severity,
				'detail'        => $detail . ( $version ? ' [WP ' . $version . ', src: ' . $source_label . ']' : '' ),
				'action'        => $action,
				'clean'         => 'none',
				'snippet'       => $snippet,
				'expected_hash' => $expected,
				'actual_hash'   => $actual,
			),
			$snippet,
			$actual ? $actual : md5( $rel . '|' . $sig )
		);

		if ( $added ) {
			if ( isset( $state['stats'][ $severity ] ) ) {
				$state['stats'][ $severity ]++;
			}
			if ( ! isset( $state['stats']['core'] ) ) {
				$state['stats']['core'] = 0;
			}
			$state['stats']['core']++;
		}
	}

	private static function save_last_summary( $state, $checksums ) {
		$issues = isset( $state['issues'] ) ? $state['issues'] : array();
		$mod = $miss = $extra = 0;
		foreach ( $issues as $iss ) {
			if ( empty( $iss['source'] ) || 'core' !== $iss['source'] ) {
				continue;
			}
			switch ( isset( $iss['sig'] ) ? $iss['sig'] : '' ) {
				case 'core_checksum_modified':
					$mod++;
					break;
				case 'core_checksum_missing':
					$miss++;
					break;
				case 'core_checksum_extra':
					$extra++;
					break;
			}
		}

		update_option(
			'mvn_core_integrity_last',
			array(
				'finished_at' => gmdate( 'c' ),
				'version'     => isset( $checksums['version'] ) ? $checksums['version'] : '',
				'source'      => isset( $checksums['source'] ) ? $checksums['source'] : '',
				'modified'    => $mod,
				'missing'     => $miss,
				'extra'       => $extra,
				'total'       => $mod + $miss + $extra,
				'ok'          => ( 0 === ( $mod + $miss + $extra ) ),
			),
			false
		);
	}

	private static function merge_standalone_issues( &$state ) {
		$new_issues = isset( $state['issues'] ) ? $state['issues'] : array();
		if ( empty( $new_issues ) ) {
			return;
		}

		$existing = MVN_Scanner::get_issues();
		$keys     = array();
		foreach ( $existing as $iss ) {
			$keys[ ( isset( $iss['rel'] ) ? $iss['rel'] : '' ) . '|' . ( isset( $iss['sig'] ) ? $iss['sig'] : '' ) ] = true;
		}

		foreach ( $new_issues as $iss ) {
			$key = ( isset( $iss['rel'] ) ? $iss['rel'] : '' ) . '|' . ( isset( $iss['sig'] ) ? $iss['sig'] : '' );
			if ( ! isset( $keys[ $key ] ) ) {
				$existing[]    = $iss;
				$keys[ $key ] = true;
			}
		}

		MVN_Incidents::store_issues( MVN_Scanner::sort_issues( $existing ) );
	}
}
