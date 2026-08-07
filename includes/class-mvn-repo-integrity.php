<?php
/**
 * Plugin (and theme where available) integrity vs wordpress.org checksums.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Repo_Integrity {

	const CHUNK = 30;

	/**
	 * Soft paths ignored in checksum compare (like WP-CLI --strict off).
	 */
	private static function soft_paths() {
		return array(
			'readme.txt',
			'readme.md',
			'changelog.txt',
			'changelog.md',
			'license.txt',
			'license.md',
			'.git',
			'.svn',
			'.DS_Store',
		);
	}

	private static function is_soft( $rel_in_plugin ) {
		$base = strtolower( basename( $rel_in_plugin ) );
		foreach ( self::soft_paths() as $soft ) {
			if ( $base === strtolower( $soft ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Begin repo integrity phase after core.
	 */
	public static function begin_phase( &$state ) {
		$jobs = self::build_jobs();
		$state['phase']           = 'repo';
		$state['repo_jobs']       = $jobs;
		$state['repo_job_cursor'] = 0;
		$state['repo_file_queue'] = array();
		$state['repo_context']    = null;
		$state['repo_total']      = 0;
		$state['repo_processed']  = 0;
		$state['total']           = max( 1, count( $jobs ) );
		$state['processed']       = 0;
		$state['cursor']          = 0;

		if ( empty( $jobs ) ) {
			$state['phase'] = 'repo_done';
		}
	}

	public static function is_done( $state ) {
		return empty( $state['phase'] ) || 'repo_done' === $state['phase'] || ( 'repo' === $state['phase'] && empty( $state['repo_jobs'] ) && empty( $state['repo_file_queue'] ) );
	}

	/**
	 * Build list of {type, slug, version, folder, name} for installed.org plugins.
	 */
	private static function build_jobs() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$jobs      = array();
		$installed = get_plugins();
		$self      = mvn_self_plugin_slugs();

		foreach ( $installed as $file => $data ) {
			$folder = dirname( $file );
			if ( '.' === $folder || false !== strpos( $folder, '/' ) ) {
				// Single-file plugins in plugins root — skip checksum API (no folder slug).
				if ( '.' === $folder ) {
					continue;
				}
			}
			$slug = $folder;
			if ( in_array( $slug, $self, true ) ) {
				continue;
			}
			$version = isset( $data['Version'] ) ? $data['Version'] : '';
			if ( ! $version ) {
				continue;
			}
			$jobs[] = array(
				'type'    => 'plugin',
				'slug'    => $slug,
				'folder'  => $folder,
				'version' => $version,
				'name'    => isset( $data['Name'] ) ? $data['Name'] : $slug,
			);
		}

		// Default themes often appear in core checksums; still try theme-checksums for.org themes.
		$themes = wp_get_themes();
		foreach ( $themes as $stylesheet => $theme ) {
			$version = $theme->get( 'Version' );
			if ( ! $version ) {
				continue;
			}
			$jobs[] = array(
				'type'    => 'theme',
				'slug'    => $stylesheet,
				'folder'  => $stylesheet,
				'version' => $version,
				'name'    => $theme->get( 'Name' ),
			);
		}

		return apply_filters( 'mvn_repo_integrity_jobs', $jobs );
	}

	/**
	 * Process one tick of repo integrity.
	 */
	public static function tick( &$state ) {
		// Ensure we have a file queue; skip packages without.org checksums.
		$guard = 0;
		while ( empty( $state['repo_file_queue'] ) && $guard < 8 ) {
			$guard++;
			if ( ! self::load_next_job( $state ) ) {
				$state['phase']           = 'repo_done';
				$state['repo_jobs']       = array();
				$state['repo_file_queue'] = array();
				$state['repo_context']    = null;
				return;
			}
			if ( empty( $state['repo_file_queue'] ) && empty( $state['repo_jobs'] ) ) {
				$state['phase'] = 'repo_done';
				return;
			}
		}

		$ctx   = isset( $state['repo_context'] ) ? $state['repo_context'] : null;
		$queue = isset( $state['repo_file_queue'] ) ? $state['repo_file_queue'] : array();
		if ( ! $ctx || empty( $queue ) ) {
			return;
		}

		$map   = isset( $ctx['files'] ) ? $ctx['files'] : array();
		$end   = min( self::CHUNK, count( $queue ) );
		$slice = array_slice( $queue, 0, $end );
		$state['repo_file_queue'] = array_slice( $queue, $end );

		$base_abs = $ctx['base_abs'];
		$prefix   = $ctx['rel_prefix'];

		foreach ( $slice as $rel_in_pkg ) {
			$state['repo_processed'] = isset( $state['repo_processed'] ) ? (int) $state['repo_processed'] + 1 : 1;
			if ( self::is_soft( $rel_in_pkg ) ) {
				continue;
			}
			$abs      = trailingslashit( $base_abs ) . str_replace( '/', DIRECTORY_SEPARATOR, $rel_in_pkg );
			$site_rel = trailingslashit( $prefix ) . $rel_in_pkg;
			$site_rel = str_replace( '\\', '/', $site_rel );

			$expected = isset( $map[ $rel_in_pkg ] ) ? $map[ $rel_in_pkg ] : null;
			if ( null === $expected ) {
				continue;
			}

			if ( ! is_file( $abs ) ) {
				self::flag(
					$state,
					$site_rel,
					'repo_checksum_missing',
					'فایل مخزن گم‌شده: ' . $ctx['name'],
					'critical',
					'quarantine',
					$ctx
				);
				continue;
			}

			$content = @file_get_contents( $abs );
			if ( false === $content ) {
				continue;
			}

			if ( ! self::hash_matches( $content, $expected ) ) {
				self::flag(
					$state,
					$site_rel,
					'repo_checksum_modified',
					'فایل تغییر یافته نسبت به wordpress.org: ' . $ctx['name'],
					'critical',
					'quarantine',
					$ctx
				);
			}
		}

		$jobs_total = isset( $state['repo_jobs_total'] ) ? (int) $state['repo_jobs_total'] : 1;
		$done_jobs  = (int) ( isset( $state['repo_job_cursor'] ) ? $state['repo_job_cursor'] : 0 );
		$state['total']     = max( 1, $jobs_total );
		$state['processed'] = min( $jobs_total, $done_jobs );
		$state['cursor']    = $state['processed'];

		if ( empty( $state['repo_file_queue'] ) ) {
			self::flag_extras( $state, $ctx );
			if ( empty( $state['repo_jobs'] ) ) {
				$state['phase'] = 'repo_done';
			}
		}
	}

	/**
	 * Load next plugin/theme checksum job into queue.
	 *
	 * @return bool False if no more jobs.
	 */
	private static function load_next_job( &$state ) {
		$jobs = isset( $state['repo_jobs'] ) ? $state['repo_jobs'] : array();
		if ( empty( $jobs ) ) {
			return false;
		}
		if ( ! isset( $state['repo_jobs_total'] ) ) {
			$state['repo_jobs_total'] = count( $jobs ) + (int) ( isset( $state['repo_job_cursor'] ) ? $state['repo_job_cursor'] : 0 );
		}

		$job = array_shift( $jobs );
		$state['repo_jobs']       = $jobs;
		$state['repo_job_cursor'] = isset( $state['repo_job_cursor'] ) ? (int) $state['repo_job_cursor'] + 1 : 1;
		$state['repo_context']    = null;
		$state['repo_file_queue'] = array();

		$checksums = self::fetch_checksums( $job['type'], $job['slug'], $job['version'] );
		if ( is_wp_error( $checksums ) || empty( $checksums['files'] ) ) {
			return ! empty( $jobs );
		}

		if ( 'plugin' === $job['type'] ) {
			$base   = trailingslashit( WP_PLUGIN_DIR ) . $job['folder'];
			$prefix = 'wp-content/plugins/' . $job['folder'];
		} else {
			$base   = trailingslashit( get_theme_root() ) . $job['folder'];
			$prefix = str_replace( '\\', '/', mvn_rel_path( $base ) );
		}

		$state['repo_context'] = array(
			'type'       => $job['type'],
			'slug'       => $job['slug'],
			'name'       => $job['name'],
			'version'    => $job['version'],
			'base_abs'   => $base,
			'rel_prefix' => $prefix,
			'files'      => $checksums['files'],
		);
		$state['repo_file_queue'] = array_keys( $checksums['files'] );
		$state['repo_label']      = $job['name'] . ' ' . $job['version'];
		return true;
	}

	/**
	 * @return array{files:array}|WP_Error
	 */
	private static function fetch_checksums( $type, $slug, $version ) {
		$slug    = sanitize_title( $slug );
		$version = preg_replace( '/[^0-9a-zA-Z.\-+]/', '', $version );
		$cache_key = 'mvn_repo_ck_' . md5( $type . '|' . $slug . '|' . $version );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) && isset( $cached['files'] ) ) {
			return $cached;
		}

		if ( 'plugin' === $type ) {
			$url = sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) );
		} else {
			$url = sprintf( 'https://downloads.wordpress.org/theme-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) );
		}

		$response = wp_remote_get( $url, array( 'timeout' => 45 ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $code ) {
			return new WP_Error( 'http', 'HTTP ' . $code );
		}
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body['files'] ) || ! is_array( $body['files'] ) ) {
			return new WP_Error( 'bad_body', 'checksum empty' );
		}

		// Normalize: each file => list of hash strings (md5/sha256).
		$files = array();
		foreach ( $body['files'] as $path => $hashes ) {
			$path = ltrim( str_replace( '\\', '/', (string) $path ), '/' );
			if ( is_string( $hashes ) ) {
				$files[ $path ] = array( $hashes );
			} elseif ( is_array( $hashes ) ) {
				$flat = array();
				foreach ( $hashes as $h ) {
					if ( is_string( $h ) ) {
						$flat[] = strtolower( $h );
					} elseif ( is_array( $h ) ) {
						foreach ( $h as $v ) {
							if ( is_string( $v ) ) {
								$flat[] = strtolower( $v );
							}
						}
					}
				}
				$files[ $path ] = array_values( array_unique( $flat ) );
			}
		}

		$out = array( 'files' => $files );
		set_transient( $cache_key, $out, DAY_IN_SECONDS );
		return $out;
	}

	private static function hash_matches( $content, $expected_list ) {
		if ( ! is_array( $expected_list ) ) {
			$expected_list = array( $expected_list );
		}
		$candidates = array(
			md5( $content ),
			hash( 'sha256', $content ),
		);
		foreach ( $expected_list as $exp ) {
			$exp = strtolower( (string) $exp );
			foreach ( $candidates as $c ) {
				if ( hash_equals( $exp, $c ) ) {
					return true;
				}
			}
		}
		return false;
	}

	private static function flag( &$state, $rel, $sig, $label, $severity, $action, $ctx ) {
		if ( MVN_Scanner::add_finding(
			$state,
			array(
				'rel'      => $rel,
				'sig'      => $sig,
				'label'    => $label,
				'severity' => $severity,
				'detail'   => isset( $ctx['slug'] ) ? ( $ctx['type'] . ':' . $ctx['slug'] . '@' . $ctx['version'] ) : '',
				'action'   => $action,
				'snippet'  => '',
				'source'   => 'repo',
			),
			'',
			''
		) ) {
			if ( ! isset( $state['stats'][ $severity ] ) ) {
				$state['stats'][ $severity ] = 0;
			}
			$state['stats'][ $severity ]++;
			if ( ! isset( $state['stats']['repo'] ) ) {
				$state['stats']['repo'] = 0;
			}
			$state['stats']['repo']++;
		}
	}

	/**
	 * Flag local files under package that are not in official checksum map.
	 */
	private static function flag_extras( &$state, $ctx ) {
		if ( empty( $ctx['base_abs'] ) || empty( $ctx['files'] ) || ! is_dir( $ctx['base_abs'] ) ) {
			return;
		}
		$map   = $ctx['files'];
		$files = mvn_list_files( $ctx['base_abs'], 100000 );
		$base  = rtrim( str_replace( '\\', '/', $ctx['base_abs'] ), '/' ) . '/';
		foreach ( $files as $site_rel ) {
			$abs = mvn_abs_path( $site_rel );
			if ( ! $abs ) {
				continue;
			}
			$abs_n = str_replace( '\\', '/', $abs );
			if ( 0 !== strpos( $abs_n, $base ) ) {
				continue;
			}
			$rel_in = substr( $abs_n, strlen( $base ) );
			if ( self::is_soft( $rel_in ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $rel_in, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, array( 'php', 'phtml', 'js', 'css' ), true ) ) {
				continue;
			}
			if ( isset( $map[ $rel_in ] ) ) {
				continue;
			}
			self::flag(
				$state,
				$site_rel,
				'repo_checksum_extra',
				'فایل اضافی نسبت به wordpress.org: ' . $ctx['name'],
				'warning',
				'quarantine_delete',
				$ctx
			);
		}
	}
}
