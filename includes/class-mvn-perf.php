<?php
/**
 * Performance profiler — SQL queries, HTTP requests, slow flags, auto-optimize.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Perf {

	const OPTION_ARM      = 'mvn_perf_arm';
	const OPTION_LAST     = 'mvn_perf_last';
	const OPTION_BLOCK    = 'mvn_perf_http_block';
	const OPTION_FAST_HTTP = 'mvn_perf_fast_http';
	const STATE_KEY       = 'perf_last';
	const SLOW_QUERY_MS   = 50;
	const SLOW_HTTP_MS    = 300;
	const BLOCK_HTTP_MS   = 2000;
	const MAX_QUERIES     = 400;
	const MAX_HTTP        = 80;

	/** @var MVN_Perf */
	private static $instance = null;

	/** @var float */
	private $boot_time = 0;

	/** @var array */
	private $http_log = array();

	/** @var array */
	private $http_starts = array();

	/** @var array */
	private $milestones = array();

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot() {
		$this->boot_time = microtime( true );

		// Always-on: shorten timeouts for non-allowlisted hosts after auto-optimize.
		add_filter( 'http_request_args', array( __CLASS__, 'filter_fast_http_args' ), 20, 2 );

		if ( ! $this->is_armed() ) {
			return;
		}

		if ( ! defined( 'SAVEQUERIES' ) ) {
			define( 'SAVEQUERIES', true );
		}

		add_action( 'plugins_loaded', array( $this, 'mark' ), 0 );
		add_action( 'plugins_loaded', array( $this, 'mark' ), 99999 );
		add_action( 'setup_theme', array( $this, 'mark' ), 0 );
		add_action( 'after_setup_theme', array( $this, 'mark' ), 99999 );
		add_action( 'init', array( $this, 'mark' ), 0 );
		add_action( 'init', array( $this, 'mark' ), 99999 );
		add_action( 'wp_loaded', array( $this, 'mark' ), 0 );
		add_action( 'admin_init', array( $this, 'mark' ), 0 );
		add_action( 'template_redirect', array( $this, 'mark' ), 0 );

		add_filter( 'pre_http_request', array( $this, 'http_start' ), 10, 3 );
		add_action( 'http_api_debug', array( $this, 'http_done' ), 10, 5 );

		add_action( 'shutdown', array( $this, 'capture' ), 997 );
	}

	public function mark() {
		$this->milestones[] = array(
			'hook' => current_filter(),
			'ms'   => round( ( microtime( true ) - $this->boot_time ) * 1000, 1 ),
		);
	}

	/**
	 * Arm profiler for a short window / limited captures.
	 */
	public static function arm( $minutes = 10, $max_captures = 5 ) {
		$arm = array(
			'until'     => time() + max( 1, (int) $minutes ) * 60,
			'max'       => max( 1, (int) $max_captures ),
			'captured'  => 0,
			'armed_at'  => gmdate( 'c' ),
			'armed_by'  => get_current_user_id(),
		);
		update_option( self::OPTION_ARM, $arm, false );
		mvn_log( 'Perf profiler armed for ' . $minutes . 'm / max ' . $arm['max'] );
		return $arm;
	}

	public static function disarm() {
		delete_option( self::OPTION_ARM );
		mvn_log( 'Perf profiler disarmed' );
		return true;
	}

	public static function arm_status() {
		$arm = get_option( self::OPTION_ARM, array() );
		if ( ! is_array( $arm ) || empty( $arm['until'] ) || time() > (int) $arm['until'] ) {
			return array(
				'active'    => false,
				'remaining' => 0,
				'captured'  => 0,
				'max'       => 0,
			);
		}
		return array(
			'active'    => true,
			'remaining' => max( 0, (int) $arm['until'] - time() ),
			'captured'  => isset( $arm['captured'] ) ? (int) $arm['captured'] : 0,
			'max'       => isset( $arm['max'] ) ? (int) $arm['max'] : 0,
			'until'     => (int) $arm['until'],
		);
	}

	private function is_armed() {
		$arm = get_option( self::OPTION_ARM, array() );
		if ( ! is_array( $arm ) || empty( $arm['until'] ) || time() > (int) $arm['until'] ) {
			return false;
		}
		$max = isset( $arm['max'] ) ? (int) $arm['max'] : 5;
		$cap = isset( $arm['captured'] ) ? (int) $arm['captured'] : 0;
		return $cap < $max;
	}

	public function http_start( $preempt, $args, $url ) {
		$key = md5( $url . microtime( true ) . wp_rand() );
		$this->http_starts[ $key ] = array(
			'url'   => $url,
			'start' => microtime( true ),
			'args'  => array(
				'method'  => isset( $args['method'] ) ? $args['method'] : 'GET',
				'timeout' => isset( $args['timeout'] ) ? $args['timeout'] : null,
			),
		);
		// Stash key on args via a side channel isn't possible; match by URL on done.
		if ( ! isset( $GLOBALS['mvn_http_pending'] ) ) {
			$GLOBALS['mvn_http_pending'] = array();
		}
		$GLOBALS['mvn_http_pending'][] = $this->http_starts[ $key ];
		return $preempt;
	}

	public function http_done( $response, $context, $class, $parsed_args, $url ) {
		$end   = microtime( true );
		$start = $end;
		if ( ! empty( $GLOBALS['mvn_http_pending'] ) ) {
			foreach ( $GLOBALS['mvn_http_pending'] as $i => $pending ) {
				if ( isset( $pending['url'] ) && $pending['url'] === $url ) {
					$start = $pending['start'];
					unset( $GLOBALS['mvn_http_pending'][ $i ] );
					$GLOBALS['mvn_http_pending'] = array_values( $GLOBALS['mvn_http_pending'] );
					break;
				}
			}
		}
		$code = 0;
		if ( is_wp_error( $response ) ) {
			$code = 0;
			$err  = $response->get_error_message();
		} else {
			$code = (int) wp_remote_retrieve_response_code( $response );
			$err  = '';
		}
		$ms = round( ( $end - $start ) * 1000, 1 );
		$host = wp_parse_url( $url, PHP_URL_HOST );
		$flags = self::classify_http( $url, $host, $ms, $code );

		if ( count( $this->http_log ) < self::MAX_HTTP ) {
			$this->http_log[] = array(
				'url'    => $url,
				'host'   => $host ? $host : '',
				'method' => isset( $parsed_args['method'] ) ? $parsed_args['method'] : 'GET',
				'ms'     => $ms,
				'code'   => $code,
				'error'  => $err,
				'flags'  => $flags,
				'slow'   => $ms >= self::SLOW_HTTP_MS,
				'risk'   => ! empty( $flags ),
			);
		}
	}

	public function capture() {
		if ( ! $this->is_armed() ) {
			return;
		}

		global $wpdb;

		$total_ms = round( ( microtime( true ) - $this->boot_time ) * 1000, 1 );
		$mem      = memory_get_peak_usage( true );

		$queries = array();
		$dup     = array();
		$slow_q  = 0;
		$total_q_ms = 0;

		if ( ! empty( $wpdb->queries ) && is_array( $wpdb->queries ) ) {
			foreach ( $wpdb->queries as $q ) {
				$sql  = isset( $q[0] ) ? $q[0] : '';
				$time = isset( $q[1] ) ? (float) $q[1] : 0;
				$caller = isset( $q[2] ) ? $q[2] : '';
				$ms   = round( $time * 1000, 2 );
				$total_q_ms += $ms;
				$norm = self::normalize_sql( $sql );
				if ( ! isset( $dup[ $norm ] ) ) {
					$dup[ $norm ] = 0;
				}
				$dup[ $norm ]++;

				$flags = self::classify_query( $sql, $ms, $caller );
				if ( $ms >= self::SLOW_QUERY_MS ) {
					$slow_q++;
				}
				if ( count( $queries ) < self::MAX_QUERIES ) {
					$queries[] = array(
						'sql'    => self::trim_sql( $sql ),
						'ms'     => $ms,
						'caller' => self::short_caller( $caller ),
						'slow'   => $ms >= self::SLOW_QUERY_MS,
						'flags'  => $flags,
						'risk'   => ! empty( $flags ),
					);
				}
			}
		}

		$duplicates = array();
		foreach ( $dup as $sql => $count ) {
			if ( $count >= 3 ) {
				$duplicates[] = array(
					'sql'   => self::trim_sql( $sql ),
					'count' => $count,
				);
			}
		}
		usort(
			$duplicates,
			function ( $a, $b ) {
				return $b['count'] - $a['count'];
			}
		);
		$duplicates = array_slice( $duplicates, 0, 30 );

		usort(
			$queries,
			function ( $a, $b ) {
				return $b['ms'] <=> $a['ms'];
			}
		);

		$autoload = self::autoload_stats();
		$orphans  = self::find_orphan_autoloads( isset( $autoload['heavy'] ) ? $autoload['heavy'] : array() );
		$autoload['orphans'] = $orphans;
		$flags_summary = self::build_flags_summary( $queries, $this->http_log, $duplicates, $autoload, $total_ms );

		$context = array(
			'is_admin'  => is_admin(),
			'ajax'      => defined( 'DOING_AJAX' ) && DOING_AJAX,
			'cron'      => defined( 'DOING_CRON' ) && DOING_CRON,
			'uri'       => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			'method'    => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
		);

		// Skip AJAX/cron noise — profile real page loads.
		if ( ! empty( $context['ajax'] ) || ! empty( $context['cron'] ) ) {
			return;
		}

		$report = array(
			'captured_at'   => gmdate( 'c' ),
			'total_ms'      => $total_ms,
			'memory'        => $mem,
			'memory_human'  => size_format( $mem ),
			'query_count'   => isset( $wpdb->num_queries ) ? (int) $wpdb->num_queries : count( $queries ),
			'query_ms'      => round( $total_q_ms, 1 ),
			'http_count'    => count( $this->http_log ),
			'slow_queries'  => $slow_q,
			'context'       => $context,
			'milestones'    => array_slice( $this->milestones, 0, 40 ),
			'queries'       => array_slice( $queries, 0, 100 ),
			'http'          => $this->http_log,
			'duplicates'    => $duplicates,
			'autoload'      => $autoload,
			'flags'         => $flags_summary,
			'plugins'       => self::active_plugin_slugs(),
		);

		update_option( self::OPTION_LAST, $report, false );
		mvn_state_write( self::STATE_KEY, $report );

		$arm = get_option( self::OPTION_ARM, array() );
		if ( is_array( $arm ) ) {
			$arm['captured'] = isset( $arm['captured'] ) ? ( (int) $arm['captured'] + 1 ) : 1;
			update_option( self::OPTION_ARM, $arm, false );
			if ( $arm['captured'] >= (int) $arm['max'] || time() > (int) $arm['until'] ) {
				// Keep arm until expiry so UI shows status; captured count stops further capture via is_armed().
			}
		}

		mvn_log( 'Perf capture: ' . $total_ms . 'ms queries=' . $report['query_count'] . ' http=' . $report['http_count'] );
	}

	public static function last_report() {
		$report = get_option( self::OPTION_LAST, array() );
		if ( ! is_array( $report ) || empty( $report ) ) {
			$report = mvn_state_read( self::STATE_KEY, array() );
		}
		return is_array( $report ) ? $report : array();
	}

	public static function clear_report() {
		delete_option( self::OPTION_LAST );
		mvn_state_delete( self::STATE_KEY );
		return true;
	}

	/**
	 * Export last performance report as CSV (UTF-8 BOM for Excel).
	 *
	 * @param array|null $report
	 * @return string
	 */
	public static function report_to_csv( $report = null ) {
		if ( null === $report ) {
			$report = self::last_report();
		}
		if ( ! is_array( $report ) ) {
			$report = array();
		}

		$fh = fopen( 'php://temp', 'r+' );
		if ( false === $fh ) {
			return '';
		}

		fwrite( $fh, "\xEF\xBB\xBF" );
		fputcsv(
			$fh,
			array(
				'بخش',
				'شدت',
				'زمان_ms',
				'تعداد',
				'کد_HTTP',
				'میزبان',
				'پرچم‌ها',
				'عنوان_یا_کلید',
				'جزئیات_SQL_یا_URL',
				'Caller',
				'کند',
				'مشکوک',
			)
		);

		$ctx = isset( $report['context'] ) && is_array( $report['context'] ) ? $report['context'] : array();
		$summary_rows = array(
			array( 'summary', '', isset( $report['total_ms'] ) ? $report['total_ms'] : '', '', '', '', '', 'زمان_لود_ms', isset( $report['total_ms'] ) ? $report['total_ms'] : '', '', '', '' ),
			array( 'summary', '', isset( $report['query_ms'] ) ? $report['query_ms'] : '', isset( $report['query_count'] ) ? $report['query_count'] : '', '', '', '', 'تعداد_کوئری', isset( $report['query_count'] ) ? $report['query_count'] : '', '', '', '' ),
			array( 'summary', '', '', isset( $report['http_count'] ) ? $report['http_count'] : '', '', '', '', 'تعداد_HTTP', isset( $report['http_count'] ) ? $report['http_count'] : '', '', '', '' ),
			array( 'summary', '', '', isset( $report['slow_queries'] ) ? $report['slow_queries'] : '', '', '', '', 'کوئری_کند', isset( $report['slow_queries'] ) ? $report['slow_queries'] : '', '', '', '' ),
			array( 'summary', '', '', '', '', '', '', 'حافظه', isset( $report['memory_human'] ) ? $report['memory_human'] : '', '', '', '' ),
			array( 'summary', '', '', '', '', '', '', 'زمان_ثبت', isset( $report['captured_at'] ) ? $report['captured_at'] : '', '', '', '' ),
			array( 'summary', '', '', '', '', '', '', 'URI', isset( $ctx['uri'] ) ? $ctx['uri'] : '', '', '', '' ),
			array( 'summary', '', '', '', '', '', '', 'is_admin', ! empty( $ctx['is_admin'] ) ? '1' : '0', '', '', '' ),
		);
		foreach ( $summary_rows as $row ) {
			fputcsv( $fh, $row );
		}

		if ( ! empty( $report['flags'] ) && is_array( $report['flags'] ) ) {
			foreach ( $report['flags'] as $flag ) {
				$sev = isset( $flag['severity'] ) ? $flag['severity'] : '';
				if ( 'critical' === $sev ) {
					$sev_label = 'بحرانی';
				} elseif ( 'warning' === $sev ) {
					$sev_label = 'هشدار';
				} else {
					$sev_label = 'اطلاع';
				}
				fputcsv(
					$fh,
					array(
						'flag',
						$sev_label,
						'',
						'',
						'',
						isset( $flag['host'] ) ? $flag['host'] : '',
						'',
						isset( $flag['label'] ) ? $flag['label'] : '',
						isset( $flag['detail'] ) ? $flag['detail'] : '',
						'',
						'',
						( 'critical' === $sev || 'warning' === $sev ) ? '1' : '0',
					)
				);
			}
		}

		if ( ! empty( $report['queries'] ) && is_array( $report['queries'] ) ) {
			foreach ( $report['queries'] as $q ) {
				$flags = isset( $q['flags'] ) && is_array( $q['flags'] ) ? implode( '|', $q['flags'] ) : '';
				fputcsv(
					$fh,
					array(
						'query',
						! empty( $q['risk'] ) ? 'مشکوک' : ( ! empty( $q['slow'] ) ? 'کند' : '' ),
						isset( $q['ms'] ) ? $q['ms'] : '',
						'',
						'',
						'',
						$flags,
						'',
						isset( $q['sql'] ) ? $q['sql'] : '',
						isset( $q['caller'] ) ? $q['caller'] : '',
						! empty( $q['slow'] ) ? '1' : '0',
						! empty( $q['risk'] ) ? '1' : '0',
					)
				);
			}
		}

		if ( ! empty( $report['duplicates'] ) && is_array( $report['duplicates'] ) ) {
			foreach ( $report['duplicates'] as $d ) {
				fputcsv(
					$fh,
					array(
						'duplicate',
						'اطلاع',
						'',
						isset( $d['count'] ) ? $d['count'] : '',
						'',
						'',
						'تکراری',
						'',
						isset( $d['sql'] ) ? $d['sql'] : '',
						'',
						'',
						'',
					)
				);
			}
		}

		if ( ! empty( $report['http'] ) && is_array( $report['http'] ) ) {
			foreach ( $report['http'] as $h ) {
				$flags = isset( $h['flags'] ) && is_array( $h['flags'] ) ? implode( '|', $h['flags'] ) : '';
				fputcsv(
					$fh,
					array(
						'http',
						! empty( $h['risk'] ) ? 'مشکوک' : ( ! empty( $h['slow'] ) ? 'کند' : '' ),
						isset( $h['ms'] ) ? $h['ms'] : '',
						'',
						isset( $h['code'] ) ? $h['code'] : '',
						isset( $h['host'] ) ? $h['host'] : '',
						$flags,
						isset( $h['method'] ) ? $h['method'] : '',
						isset( $h['url'] ) ? $h['url'] : '',
						isset( $h['error'] ) ? $h['error'] : '',
						! empty( $h['slow'] ) ? '1' : '0',
						! empty( $h['risk'] ) ? '1' : '0',
					)
				);
			}
		}

		if ( ! empty( $report['autoload']['heavy'] ) && is_array( $report['autoload']['heavy'] ) ) {
			fputcsv(
				$fh,
				array(
					'autoload_summary',
					'',
					'',
					isset( $report['autoload']['count'] ) ? $report['autoload']['count'] : '',
					'',
					'',
					'',
					'جمع_بایت',
					isset( $report['autoload']['total_bytes'] ) ? $report['autoload']['total_bytes'] : '',
					'',
					'',
					'',
				)
			);
			if ( ! empty( $report['autoload']['orphans'] ) && is_array( $report['autoload']['orphans'] ) ) {
				foreach ( $report['autoload']['orphans'] as $o ) {
					fputcsv(
						$fh,
						array(
							'autoload_orphan',
							'هشدار',
							'',
							isset( $o['bytes'] ) ? $o['bytes'] : '',
							'',
							'',
							'یتیم_پلاگین_حذف‌شده',
							isset( $o['source'] ) ? $o['source'] : '',
							isset( $o['option_name'] ) ? $o['option_name'] : '',
							'',
							'',
							'1',
						)
					);
				}
			}
			foreach ( $report['autoload']['heavy'] as $o ) {
				fputcsv(
					$fh,
					array(
						'autoload',
						'',
						'',
						isset( $o['bytes'] ) ? $o['bytes'] : '',
						'',
						'',
						'',
						isset( $o['option_name'] ) ? $o['option_name'] : '',
						isset( $o['bytes'] ) ? $o['bytes'] : '',
						'',
						'',
						'',
					)
				);
			}
		}

		if ( ! empty( $report['milestones'] ) && is_array( $report['milestones'] ) ) {
			foreach ( $report['milestones'] as $m ) {
				fputcsv(
					$fh,
					array(
						'milestone',
						'',
						isset( $m['ms'] ) ? $m['ms'] : '',
						'',
						'',
						'',
						'',
						isset( $m['hook'] ) ? $m['hook'] : '',
						'',
						'',
						'',
						'',
					)
				);
			}
		}

		foreach ( self::blocked_hosts() as $host ) {
			fputcsv(
				$fh,
				array(
					'blocked_host',
					'',
					'',
					'',
					'',
					$host,
					'مسدود',
					$host,
					'',
					'',
					'',
					'1',
				)
			);
		}

		rewind( $fh );
		$csv = stream_get_contents( $fh );
		fclose( $fh );
		return is_string( $csv ) ? $csv : '';
	}

	/* ===================== Classification ===================== */

	public static function classify_http( $url, $host, $ms, $code ) {
		$flags = array();
		$host  = strtolower( (string) $host );
		if ( ! $host ) {
			$flags[] = 'host_خالی';
			return $flags;
		}

		$allow = self::http_allowlist();
		$allowed = false;
		foreach ( $allow as $suffix ) {
			if ( $host === $suffix || substr( $host, -strlen( '.' . $suffix ) ) === '.' . $suffix ) {
				$allowed = true;
				break;
			}
		}

		if ( ! $allowed ) {
			$flags[] = 'درخواست_خارجی';
		}
		if ( preg_match( '/^\d{1,3}(\.\d{1,3}){3}$/', $host ) ) {
			$flags[] = 'اتصال_به_IP';
		}
		if ( 0 === strpos( $url, 'http://' ) ) {
			$flags[] = 'HTTP_ناامن';
		}
		if ( preg_match( '/(?:pastebin|ngrok|raw\.githubusercontent|bit\.ly|tinyurl|webhook\.site|requestbin|burpcollaborator)/i', $host . $url ) ) {
			$flags[] = 'دامنه_مشکوک';
		}
		if ( $ms >= self::SLOW_HTTP_MS ) {
			$flags[] = 'کند';
		}
		if ( 0 === $code ) {
			$flags[] = 'خطای_شبکه';
		}

		$blocked = self::blocked_hosts();
		foreach ( $blocked as $b ) {
			if ( $host === $b || substr( $host, -strlen( '.' . $b ) ) === '.' . $b ) {
				$flags[] = 'مسدود_شده';
			}
		}

		return array_values( array_unique( $flags ) );
	}

	public static function classify_query( $sql, $ms, $caller ) {
		$flags = array();
		$sql_l = strtolower( $sql );
		if ( $ms >= self::SLOW_QUERY_MS ) {
			$flags[] = 'کند';
		}
		if ( false !== strpos( $sql_l, 'autoload' ) && ( false !== strpos( $sql_l, 'select' ) ) && preg_match( '/select\s+\*/i', $sql ) ) {
			$flags[] = 'autoload_سنگین';
		}
		if ( preg_match( '/(?:sleep\s*\(|benchmark\s*\(|information_schema|into\s+outfile|load_file\s*\()/i', $sql ) ) {
			$flags[] = 'SQL_مشکوک';
		}
		if ( preg_match( '/(?:eval|base64_decode|gzinflate|assert)\s*\(/i', $sql ) ) {
			$flags[] = 'کد_اجرایی_در_SQL';
		}
		if ( preg_match( '/(?:\/tmp\/|wp-content\/uploads\/.*\.php)/i', $caller . $sql ) ) {
			$flags[] = 'مسیر_مشکوک';
		}
		return $flags;
	}

	private static function http_allowlist() {
		$home_host = wp_parse_url( home_url(), PHP_URL_HOST );
		$list      = array(
			'wordpress.org',
			'api.wordpress.org',
			'downloads.wordpress.org',
			'plugins.svn.wordpress.org',
			'fonts.googleapis.com',
			'fonts.gstatic.com',
			'www.google.com',
			'www.gstatic.com',
			'youtube.com',
			'www.youtube.com',
			'vimeo.com',
			'cdnjs.cloudflare.com',
			'ajax.googleapis.com',
			'elementor.com',
			'my.elementor.com',
			'assets.elementor.com',
			'rankmath.com',
			'woocommerce.com',
			'api.woocommerce.com',
			'gravitec.net',
			'cdn.jsdelivr.net',
			'unpkg.com',
			'gtranslate.io',
			'cdn.gtranslate.net',
		);
		if ( $home_host ) {
			$list[] = strtolower( $home_host );
		}
		return apply_filters( 'mvn_perf_http_allowlist', $list );
	}

	public static function blocked_hosts() {
		$hosts = get_option( self::OPTION_BLOCK, array() );
		return is_array( $hosts ) ? array_values( array_unique( array_filter( array_map( 'strtolower', $hosts ) ) ) ) : array();
	}

	public static function block_host( $host ) {
		$host = strtolower( preg_replace( '/[^a-z0-9\.\-]/i', '', (string) $host ) );
		if ( ! $host ) {
			return false;
		}
		$hosts   = self::blocked_hosts();
		$hosts[] = $host;
		$hosts   = array_values( array_unique( $hosts ) );
		update_option( self::OPTION_BLOCK, $hosts, false );
		return true;
	}

	private static function build_flags_summary( $queries, $http, $duplicates, $autoload, $total_ms ) {
		$items = array();

		if ( $total_ms > 2000 ) {
			$items[] = array(
				'id'       => 'slow_page',
				'severity' => 'warning',
				'label'    => 'زمان لود بالای ۲ ثانیه',
				'detail'   => $total_ms . ' ms',
				'fixable'  => true,
			);
		}
		if ( count( $queries ) > 150 ) {
			$items[] = array(
				'id'       => 'too_many_queries',
				'severity' => 'warning',
				'label'    => 'تعداد کوئری بالا',
				'detail'   => count( $queries ) . ' کوئری',
				'fixable'  => true,
			);
		}
		foreach ( $http as $h ) {
			if ( empty( $h['risk'] ) ) {
				continue;
			}
			$items[] = array(
				'id'       => 'http_' . md5( isset( $h['url'] ) ? $h['url'] : '' ),
				'severity' => in_array( 'دامنه_مشکوک', isset( $h['flags'] ) ? $h['flags'] : array(), true ) || in_array( 'اتصال_به_IP', isset( $h['flags'] ) ? $h['flags'] : array(), true ) ? 'critical' : 'warning',
				'label'    => 'درخواست HTTP مشکوک/کند',
				'detail'   => ( isset( $h['host'] ) ? $h['host'] : '' ) . ' — ' . implode( ', ', isset( $h['flags'] ) ? $h['flags'] : array() ),
				'host'     => isset( $h['host'] ) ? $h['host'] : '',
				'fixable'  => true,
			);
		}
		foreach ( array_slice( $duplicates, 0, 5 ) as $d ) {
			$items[] = array(
				'id'       => 'dup_' . md5( $d['sql'] ),
				'severity' => 'info',
				'label'    => 'کوئری تکراری',
				'detail'   => $d['count'] . '× — ' . substr( $d['sql'], 0, 120 ),
				'fixable'  => true,
			);
		}
		if ( ! empty( $autoload['total_bytes'] ) && $autoload['total_bytes'] > 1024 * 1024 ) {
			$items[] = array(
				'id'       => 'autoload_heavy',
				'severity' => 'warning',
				'label'    => 'autoload سنگین در wp_options',
				'detail'   => size_format( $autoload['total_bytes'] ) . ' — ' . (int) $autoload['count'] . ' option',
				'fixable'  => true,
			);
		}
		if ( ! empty( $autoload['orphans'] ) && is_array( $autoload['orphans'] ) ) {
			$bytes = 0;
			$names = array();
			foreach ( $autoload['orphans'] as $o ) {
				$bytes += isset( $o['bytes'] ) ? (int) $o['bytes'] : 0;
				$names[] = isset( $o['option_name'] ) ? $o['option_name'] : '';
			}
			$items[] = array(
				'id'       => 'autoload_orphans',
				'severity' => 'warning',
				'label'    => 'باقی‌مانده پلاگین/قالب حذف‌شده در autoload',
				'detail'   => size_format( $bytes ) . ' — ' . implode( ', ', array_slice( array_filter( $names ), 0, 6 ) ),
				'fixable'  => true,
			);
		}
		foreach ( $queries as $q ) {
			if ( empty( $q['risk'] ) ) {
				continue;
			}
			if ( in_array( 'SQL_مشکوک', $q['flags'], true ) || in_array( 'کد_اجرایی_در_SQL', $q['flags'], true ) ) {
				$items[] = array(
					'id'       => 'sql_' . md5( $q['sql'] ),
					'severity' => 'critical',
					'label'    => 'کوئری مشکوک امنیتی',
					'detail'   => substr( $q['sql'], 0, 160 ),
					'fixable'  => false,
				);
			}
		}

		return $items;
	}

	private static function autoload_stats() {
		global $wpdb;
		$row = $wpdb->get_row(
			"SELECT COUNT(*) AS c, SUM(LENGTH(option_value)) AS s FROM {$wpdb->options} WHERE autoload IN ('yes','on','auto','autoon')",
			ARRAY_A
		);
		$heavy = $wpdb->get_results(
			"SELECT option_name, LENGTH(option_value) AS bytes FROM {$wpdb->options}
			WHERE autoload IN ('yes','on','auto','autoon')
			ORDER BY bytes DESC LIMIT 15",
			ARRAY_A
		);
		return array(
			'count'       => isset( $row['c'] ) ? (int) $row['c'] : 0,
			'total_bytes' => isset( $row['s'] ) ? (int) $row['s'] : 0,
			'heavy'       => is_array( $heavy ) ? $heavy : array(),
		);
	}

	private static function active_plugin_slugs() {
		if ( ! function_exists( 'get_option' ) ) {
			return array();
		}
		$active = get_option( 'active_plugins', array() );
		$out    = array();
		foreach ( (array) $active as $file ) {
			$out[] = dirname( $file );
		}
		return array_values( array_unique( $out ) );
	}

	private static function normalize_sql( $sql ) {
		$sql = preg_replace( '/\s+/', ' ', trim( $sql ) );
		$sql = preg_replace( '/\b\d+\b/', 'N', $sql );
		$sql = preg_replace( "/'[^']*'/", "'?'", $sql );
		return substr( $sql, 0, 300 );
	}

	private static function trim_sql( $sql ) {
		$sql = preg_replace( '/\s+/', ' ', trim( $sql ) );
		return function_exists( 'mb_substr' ) ? mb_substr( $sql, 0, 400 ) : substr( $sql, 0, 400 );
	}

	private static function short_caller( $caller ) {
		$caller = preg_replace( '/\s+/', ' ', trim( (string) $caller ) );
		return function_exists( 'mb_substr' ) ? mb_substr( $caller, 0, 180 ) : substr( $caller, 0, 180 );
	}

	/* ===================== Optimize ===================== */

	/**
	 * Safe automatic optimizations driven by the last profiler report.
	 *
	 * @return array {actions:[], blocked_hosts:[], message:string}
	 */
	public static function optimize() {
		global $wpdb;

		$actions = array();
		$report  = self::last_report();

		// 1) Expired transients.
		$deleted = self::purge_expired_transients();
		if ( $deleted > 0 ) {
			$actions[] = array(
				'id'    => 'transients',
				'label' => 'پاکسازی transientهای منقضی',
				'count' => $deleted,
			);
		}

		// 2) Orphan timeout rows without value.
		$orphans = (int) $wpdb->query(
			"DELETE a FROM {$wpdb->options} a
			LEFT JOIN {$wpdb->options} b ON b.option_name = CONCAT('_transient_', SUBSTRING(a.option_name, 20))
			WHERE a.option_name LIKE '\_transient\_timeout\_%' AND b.option_id IS NULL"
		);
		$orphans += (int) $wpdb->query(
			"DELETE a FROM {$wpdb->options} a
			LEFT JOIN {$wpdb->options} b ON b.option_name = CONCAT('_site_transient_', SUBSTRING(a.option_name, 25))
			WHERE a.option_name LIKE '\_site\_transient\_timeout\_%' AND b.option_id IS NULL"
		);
		if ( $orphans > 0 ) {
			$actions[] = array(
				'id'    => 'orphan_transients',
				'label' => 'حذف transientهای یتیم',
				'count' => $orphans,
			);
		}

		// 3) Block slow/failing external hosts from last profile (biggest real-world win).
		// Example: medpress.net theme-updater hanging ~6s × 5 ≈ 30s of a 32s admin load.
		$blocked_now = self::auto_block_hosts_from_report( $report );
		if ( $blocked_now ) {
			$actions[] = array(
				'id'    => 'block_hosts',
				'label' => 'مسدودسازی دامنه کند/خراب (علت اصلی کندی)',
				'count' => count( $blocked_now ),
				'hosts' => $blocked_now,
			);
		}

		// 3b) Cap HTTP timeouts for non-allowlisted hosts on every future request.
		update_option( self::OPTION_FAST_HTTP, 1, false );
		$actions[] = array(
			'id'    => 'fast_http',
			'label' => 'محدود کردن timeout درخواست‌های خارجی غیرضروری (۲ ثانیه)',
			'count' => 1,
		);

		// 4) Autoload: demote very large non-critical options.
		$demoted = self::demote_heavy_autoload();
		if ( $demoted > 0 ) {
			$actions[] = array(
				'id'    => 'autoload',
				'label' => 'خاموش کردن autoload برای optionهای سنگین غیرضروری',
				'count' => $demoted,
			);
		}

		// 4b) Orphan options from deleted plugins/themes (RevSlider, Xtra, …).
		$orphan_clean = self::purge_orphan_plugin_options( true );
		if ( ! empty( $orphan_clean['count'] ) ) {
			$actions[] = array(
				'id'      => 'orphan_options',
				'label'   => 'حذف/خاموش‌کردن autoload باقی‌مانده پلاگین‌های حذف‌شده',
				'count'   => (int) $orphan_clean['count'],
				'bytes'   => isset( $orphan_clean['bytes'] ) ? (int) $orphan_clean['bytes'] : 0,
				'options' => isset( $orphan_clean['options'] ) ? $orphan_clean['options'] : array(),
			);
		}

		// 5) Limit post revisions clutter.
		$revisions = self::prune_old_revisions( 20, 200 );
		if ( $revisions > 0 ) {
			$actions[] = array(
				'id'    => 'revisions',
				'label' => 'حذف revisionهای قدیمی',
				'count' => $revisions,
			);
		}

		// 5b) Purge old Action Scheduler junk (completed/failed) that slows admin menus.
		$as_purged = self::purge_old_action_scheduler( 7, 500 );
		if ( $as_purged > 0 ) {
			$actions[] = array(
				'id'    => 'action_scheduler',
				'label' => 'پاکسازی Action Scheduler قدیمی',
				'count' => $as_purged,
			);
		}

		// 6) Optimize main tables (quick).
		$tables = array( $wpdb->options, $wpdb->posts, $wpdb->postmeta, $wpdb->terms, $wpdb->term_taxonomy, $wpdb->comments );
		foreach ( $tables as $t ) {
			$wpdb->query( "OPTIMIZE TABLE `{$t}`" ); // phpcs:ignore WordPress.DB.PreparedSQL
		}
		$actions[] = array(
			'id'    => 'optimize_tables',
			'label' => 'OPTIMIZE TABLE روی جداول اصلی',
			'count' => count( $tables ),
		);

		// 7) Object / page cache flush.
		if ( function_exists( 'wp_cache_flush' ) ) {
			wp_cache_flush();
			$actions[] = array(
				'id'    => 'cache_flush',
				'label' => 'خالی کردن object cache',
				'count' => 1,
			);
		}
		if ( has_action( 'litespeed_purge_all' ) ) {
			do_action( 'litespeed_purge_all' );
			$actions[] = array(
				'id'    => 'litespeed_purge',
				'label' => 'پاکسازی کش LiteSpeed',
				'count' => 1,
			);
		}

		mvn_log( 'Perf optimize done: ' . wp_json_encode( wp_list_pluck( $actions, 'id' ) ) );

		$msg = 'بهینه‌سازی انجام شد.';
		if ( $blocked_now ) {
			$msg .= ' دامنه‌های کند مسدود شدند: ' . implode( ', ', $blocked_now ) . '.';
			$msg .= ' لود بعدی باید به‌مراتب سریع‌تر باشد.';
		}

		return array(
			'actions'       => $actions,
			'blocked_hosts' => self::blocked_hosts(),
			'message'       => $msg,
		);
	}

	/**
	 * Decide which hosts from a profiler report should be blocked.
	 *
	 * @param array $report Last report.
	 * @return string[] Newly blocked hosts.
	 */
	public static function auto_block_hosts_from_report( $report ) {
		if ( empty( $report['http'] ) || ! is_array( $report['http'] ) ) {
			return array();
		}

		$stats = array();
		foreach ( $report['http'] as $h ) {
			$host = isset( $h['host'] ) ? strtolower( (string) $h['host'] ) : '';
			if ( ! $host || self::host_is_allowlisted( $host ) ) {
				continue;
			}
			if ( ! isset( $stats[ $host ] ) ) {
				$stats[ $host ] = array(
					'count'   => 0,
					'fail'    => 0,
					'max_ms'  => 0,
					'sum_ms'  => 0,
					'flags'   => array(),
				);
			}
			$ms   = isset( $h['ms'] ) ? (float) $h['ms'] : 0;
			$code = isset( $h['code'] ) ? (int) $h['code'] : 0;
			$flags = isset( $h['flags'] ) && is_array( $h['flags'] ) ? $h['flags'] : array();

			$stats[ $host ]['count']++;
			$stats[ $host ]['sum_ms'] += $ms;
			$stats[ $host ]['max_ms']  = max( $stats[ $host ]['max_ms'], $ms );
			$stats[ $host ]['flags']   = array_values( array_unique( array_merge( $stats[ $host ]['flags'], $flags ) ) );
			if ( 0 === $code || $code >= 500 || in_array( 'خطای_شبکه', $flags, true ) ) {
				$stats[ $host ]['fail']++;
			}
		}

		$blocked_now = array();
		foreach ( $stats as $host => $s ) {
			$should = false;
			if ( array_intersect( $s['flags'], array( 'دامنه_مشکوک', 'اتصال_به_IP' ) ) ) {
				$should = true;
			}
			// Failed external updater / API (cURL empty reply, timeouts, …).
			if ( $s['fail'] > 0 && in_array( 'درخواست_خارجی', $s['flags'], true ) ) {
				$should = true;
			}
			// Extremely slow external host even without hard fail.
			if ( $s['max_ms'] >= self::BLOCK_HTTP_MS && in_array( 'درخواست_خارجی', $s['flags'], true ) ) {
				$should = true;
			}
			// Repeated slow hits (≥2) totaling serious delay.
			if ( $s['count'] >= 2 && $s['sum_ms'] >= 4000 && in_array( 'درخواست_خارجی', $s['flags'], true ) ) {
				$should = true;
			}

			if ( $should && self::block_host( $host ) ) {
				$blocked_now[] = $host;
				// Also push into HTTP Guard blocklist when available.
				if ( class_exists( 'MVN_Http_Guard', false ) && method_exists( 'MVN_Http_Guard', 'block_host' ) ) {
					MVN_Http_Guard::block_host( $host );
				}
			}
		}

		return array_values( array_unique( $blocked_now ) );
	}

	/**
	 * @param string $host Host.
	 * @return bool
	 */
	public static function host_is_allowlisted( $host ) {
		$host = strtolower( (string) $host );
		foreach ( self::http_allowlist() as $suffix ) {
			$suffix = strtolower( (string) $suffix );
			if ( $host === $suffix || substr( $host, -strlen( '.' . $suffix ) ) === '.' . $suffix ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Cap timeouts for non-allowlisted HTTP after auto-optimize.
	 *
	 * @param array  $args Request args.
	 * @param string $url  URL.
	 * @return array
	 */
	public static function filter_fast_http_args( $args, $url ) {
		if ( ! get_option( self::OPTION_FAST_HTTP, 0 ) ) {
			return $args;
		}
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( ! $host || self::host_is_allowlisted( $host ) ) {
			return $args;
		}
		// Never let a dead theme/plugin updater stall admin for 5–15s.
		$cap = 2;
		if ( ! isset( $args['timeout'] ) || (float) $args['timeout'] > $cap ) {
			$args['timeout'] = $cap;
		}
		if ( ! isset( $args['redirection'] ) || (int) $args['redirection'] > 2 ) {
			$args['redirection'] = 2;
		}
		return $args;
	}

	/**
	 * Delete old completed/failed Action Scheduler rows.
	 *
	 * @param int $days  Age in days.
	 * @param int $limit Max rows.
	 * @return int
	 */
	private static function purge_old_action_scheduler( $days = 7, $limit = 500 ) {
		global $wpdb;
		$table = $wpdb->prefix . 'actionscheduler_actions';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$exists = $wpdb->get_var( "SHOW TABLES LIKE '" . esc_sql( $table ) . "'" );
		if ( $exists !== $table ) {
			return 0;
		}
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( max( 1, (int) $days ) * DAY_IN_SECONDS ) );
		$limit  = max( 1, (int) $limit );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$n = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM `{$table}` WHERE status IN ('complete','failed','canceled') AND scheduled_date_gmt < %s LIMIT {$limit}",
				$cutoff
			)
		);
		return max( 0, $n );
	}

	private static function purge_expired_transients() {
		global $wpdb;
		$time = time();
		$n    = 0;

		$expired = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options}
				WHERE option_name LIKE '\_transient\_timeout\_%' AND option_value < %d LIMIT 500",
				$time
			)
		);
		foreach ( (array) $expired as $timeout_name ) {
			$key = str_replace( '_transient_timeout_', '', $timeout_name );
			delete_option( $timeout_name );
			delete_option( '_transient_' . $key );
			$n++;
		}

		$expired = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options}
				WHERE option_name LIKE '\_site\_transient\_timeout\_%' AND option_value < %d LIMIT 500",
				$time
			)
		);
		foreach ( (array) $expired as $timeout_name ) {
			$key = str_replace( '_site_transient_timeout_', '', $timeout_name );
			delete_option( $timeout_name );
			delete_option( '_site_transient_' . $key );
			$n++;
		}
		return $n;
	}

	private static function demote_heavy_autoload() {
		global $wpdb;
		// Only demote leftover/expired-style or clearly cache keys — never core options.
		$safe_prefixes = array(
			'_transient_',
			'_site_transient_',
			'wf_',
			'wfls_',
			'jetpack_',
			'_jetpack_',
		);
		$rows = $wpdb->get_results(
			"SELECT option_id, option_name, LENGTH(option_value) AS bytes FROM {$wpdb->options}
			WHERE autoload IN ('yes','on','auto','autoon') AND LENGTH(option_value) > 102400
			ORDER BY bytes DESC LIMIT 30",
			ARRAY_A
		);
		$n = 0;
		foreach ( (array) $rows as $row ) {
			$name = $row['option_name'];
			$ok   = false;
			foreach ( $safe_prefixes as $p ) {
				if ( 0 === strpos( $name, $p ) ) {
					$ok = true;
					break;
				}
			}
			if ( ! $ok ) {
				continue;
			}
			if ( in_array( $name, mvn_db_protected_options(), true ) ) {
				continue;
			}
			$wpdb->update( $wpdb->options, array( 'autoload' => 'no' ), array( 'option_id' => (int) $row['option_id'] ) );
			$n++;
		}
		return $n;
	}

	/**
	 * Known option leftovers mapped to plugins/themes that own them.
	 * If none of the providers are installed, the option is an orphan.
	 *
	 * @return array[]
	 */
	public static function orphan_option_rules() {
		return array(
			array(
				'label'    => 'Xtra / Codevz Theme',
				'themes'   => array( 'xtra', 'codevz' ),
				'plugins'  => array( 'codevz-plus/codevz-plus.php', 'xtra-plus/xtra-plus.php' ),
				'exact'    => array(
					'codevz_theme_options',
					'xtra_cache_selectors',
					'xtra_uninstall_jewelry',
					'codevz_options',
					'codevz_css_rtl',
					'codevz_css',
				),
				'prefixes' => array( 'codevz_', 'xtra_' ),
			),
			array(
				'label'    => 'Slider Revolution',
				'themes'   => array(),
				'plugins'  => array( 'revslider/revslider.php', 'revslider-standalone/revslider.php' ),
				'exact'    => array( 'revslider-addons', 'revslider-notices', 'revslider-global-settings' ),
				'prefixes' => array( 'revslider' ),
			),
			array(
				'label'    => 'WOOF Product Filter',
				'themes'   => array(),
				'plugins'  => array(
					'woocommerce-products-filter/index.php',
					'woocommerce-products-filter/woocommerce-products-filter.php',
				),
				'exact'    => array( 'woof_settings', 'woof_ext' ),
				'prefixes' => array( 'woof_' ),
			),
		);
	}

	/**
	 * Whether any owning plugin/theme for a rule is still installed.
	 *
	 * @param array $rule
	 * @return bool
	 */
	private static function orphan_provider_present( $rule ) {
		foreach ( (array) ( isset( $rule['plugins'] ) ? $rule['plugins'] : array() ) as $file ) {
			$file = ltrim( str_replace( '\\', '/', (string) $file ), '/' );
			if ( ! $file ) {
				continue;
			}
			// Active or merely present on disk counts as "still installed".
			if ( function_exists( 'is_plugin_active' ) && is_plugin_active( $file ) ) {
				return true;
			}
			if ( defined( 'WP_PLUGIN_DIR' ) && is_file( WP_PLUGIN_DIR . '/' . $file ) ) {
				return true;
			}
			// Directory-only slug.
			$dir = dirname( $file );
			if ( $dir && '.' !== $dir && defined( 'WP_PLUGIN_DIR' ) && is_dir( WP_PLUGIN_DIR . '/' . $dir ) ) {
				return true;
			}
		}

		$stylesheet = function_exists( 'get_stylesheet' ) ? get_stylesheet() : '';
		$template   = function_exists( 'get_template' ) ? get_template() : '';
		foreach ( (array) ( isset( $rule['themes'] ) ? $rule['themes'] : array() ) as $slug ) {
			$slug = strtolower( (string) $slug );
			if ( ! $slug ) {
				continue;
			}
			// فقط اگر قالب واقعاً فعال باشد مالک محسوب می‌شود (پوشهٔ بلااستفاده مانع پاکسازی نشود).
			if ( $stylesheet === $slug || $template === $slug ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match option name to an orphan rule (provider missing).
	 *
	 * @param string $name
	 * @return array|null
	 */
	private static function match_orphan_rule( $name ) {
		$name = (string) $name;
		foreach ( self::orphan_option_rules() as $rule ) {
			if ( self::orphan_provider_present( $rule ) ) {
				continue;
			}
			foreach ( (array) ( isset( $rule['exact'] ) ? $rule['exact'] : array() ) as $exact ) {
				if ( $name === $exact ) {
					return $rule;
				}
			}
			foreach ( (array) ( isset( $rule['prefixes'] ) ? $rule['prefixes'] : array() ) as $prefix ) {
				if ( $prefix && 0 === strpos( $name, $prefix ) ) {
					return $rule;
				}
			}
		}
		return null;
	}

	/**
	 * Find autoloaded options belonging to deleted plugins/themes.
	 *
	 * @param array $heavy_rows Optional rows from autoload_stats heavy list.
	 * @return array
	 */
	public static function find_orphan_autoloads( $heavy_rows = null ) {
		global $wpdb;

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( null === $heavy_rows ) {
			$heavy_rows = $wpdb->get_results(
				"SELECT option_name, LENGTH(option_value) AS bytes FROM {$wpdb->options}
				WHERE autoload IN ('yes','on','auto','autoon')
				ORDER BY bytes DESC LIMIT 80",
				ARRAY_A
			);
		}

		$out = array();
		foreach ( (array) $heavy_rows as $row ) {
			$name = isset( $row['option_name'] ) ? $row['option_name'] : '';
			if ( ! $name || in_array( $name, mvn_db_protected_options(), true ) ) {
				continue;
			}
			$rule = self::match_orphan_rule( $name );
			if ( ! $rule ) {
				continue;
			}
			$out[] = array(
				'option_name' => $name,
				'bytes'       => isset( $row['bytes'] ) ? (int) $row['bytes'] : 0,
				'source'      => isset( $rule['label'] ) ? $rule['label'] : '',
			);
		}
		return $out;
	}

	/**
	 * Remove or demote orphan options from deleted plugins/themes.
	 *
	 * @param bool $delete When true, delete option rows; otherwise only autoload=no.
	 * @return array{count:int,bytes:int,options:string[],mode:string}
	 */
	public static function purge_orphan_plugin_options( $delete = true ) {
		global $wpdb;

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$rows = $wpdb->get_results(
			"SELECT option_id, option_name, LENGTH(option_value) AS bytes, autoload FROM {$wpdb->options}
			ORDER BY bytes DESC LIMIT 500",
			ARRAY_A
		);

		$count   = 0;
		$bytes   = 0;
		$options = array();

		foreach ( (array) $rows as $row ) {
			$name = isset( $row['option_name'] ) ? $row['option_name'] : '';
			if ( ! $name || in_array( $name, mvn_db_protected_options(), true ) ) {
				continue;
			}
			$rule = self::match_orphan_rule( $name );
			if ( ! $rule ) {
				continue;
			}

			$b = isset( $row['bytes'] ) ? (int) $row['bytes'] : 0;
			if ( $delete ) {
				delete_option( $name );
				// Site options (multisite network) — best effort.
				if ( is_multisite() && function_exists( 'delete_site_option' ) ) {
					delete_site_option( $name );
				}
			} else {
				$wpdb->update(
					$wpdb->options,
					array( 'autoload' => 'no' ),
					array( 'option_id' => (int) $row['option_id'] )
				);
			}
			$count++;
			$bytes += $b;
			$options[] = $name . ' (' . ( isset( $rule['label'] ) ? $rule['label'] : '?' ) . ')';
			if ( $count >= 80 ) {
				break;
			}
		}

		if ( $count > 0 ) {
			wp_cache_delete( 'alloptions', 'options' );
			mvn_log( 'Perf purged orphan options: ' . $count . ' / ' . $bytes . ' bytes — ' . implode( ', ', $options ) );
		}

		return array(
			'count'   => $count,
			'bytes'   => $bytes,
			'options' => $options,
			'mode'    => $delete ? 'delete' : 'demote',
		);
	}

	private static function prune_old_revisions( $keep_per_post, $limit ) {
		global $wpdb;
		$keep_per_post = max( 5, (int) $keep_per_post );
		$limit         = max( 10, (int) $limit );
		$ids           = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT ID FROM {$wpdb->posts} WHERE post_type = 'revision' ORDER BY post_date ASC LIMIT %d",
				$limit * 3
			)
		);
		if ( empty( $ids ) ) {
			return 0;
		}
		// Simpler safe approach: delete oldest revisions beyond global cap for this run.
		$deleted = 0;
		foreach ( array_slice( $ids, 0, $limit ) as $id ) {
			// Keep recent ones: only delete if parent already has many.
			$parent = (int) $wpdb->get_var( $wpdb->prepare( "SELECT post_parent FROM {$wpdb->posts} WHERE ID = %d", $id ) );
			if ( ! $parent ) {
				continue;
			}
			$count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_parent = %d AND post_type = 'revision'", $parent ) );
			if ( $count <= $keep_per_post ) {
				continue;
			}
			wp_delete_post_revision( $id );
			$deleted++;
			if ( $deleted >= $limit ) {
				break;
			}
		}
		return $deleted;
	}
}

/**
 * Block HTTP to hosts marked by optimizer (front + admin).
 */
function mvn_perf_block_http( $preempt, $args, $url ) {
	$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
	if ( ! $host ) {
		return $preempt;
	}
	foreach ( MVN_Perf::blocked_hosts() as $b ) {
		if ( $host === $b || substr( $host, -strlen( '.' . $b ) ) === '.' . $b ) {
			return new WP_Error( 'mvn_http_blocked', 'درخواست به دامنه مسدودشده توسط آنتی‌ویروس محتوانگار: ' . $host );
		}
	}
	return $preempt;
}
add_filter( 'pre_http_request', 'mvn_perf_block_http', 5, 3 );
