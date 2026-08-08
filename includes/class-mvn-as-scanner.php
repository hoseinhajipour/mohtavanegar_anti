<?php
/**
 * Action Scheduler scanner — detect suspicious scheduled actions and clean them.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_AS_Scanner {

	const STATE_KEY = 'as_scan';
	const CHUNK     = 40;

	/**
	 * Attach AS phase to an active full-scan job.
	 */
	public static function begin_phase( &$state ) {
		$meta = self::table_meta();

		$state['phase']          = 'as';
		$state['as_available']   = $meta['available'] ? 1 : 0;
		$state['as_table']       = $meta['actions'];
		$state['as_logs_table']  = $meta['logs'];
		$state['as_cursor']      = 0;
		$state['as_total']       = $meta['count'];
		$state['as_processed']   = 0;
		$state['total']          = $meta['count'];
		$state['processed']      = 0;
		$state['cursor']         = 0;
		$state['files']          = array();
		$state['all_files']      = array();

		if ( ! isset( $state['stats']['as'] ) ) {
			$state['stats']['as'] = 0;
		}

		if ( ! $meta['available'] ) {
			// Nothing to scan — mark as done immediately.
			$state['as_cursor'] = 0;
			mvn_log( 'AS scan phase skipped: Action Scheduler tables not found' );
			return;
		}

		mvn_log( 'AS scan phase started: total actions=' . $meta['count'] );
	}

	/**
	 * Process one chunk of Action Scheduler rows.
	 */
	public static function tick( &$state ) {
		if ( empty( $state['as_available'] ) ) {
			return;
		}

		$table = isset( $state['as_table'] ) ? $state['as_table'] : '';
		if ( ! $table ) {
			$state['as_available'] = 0;
			return;
		}

		global $wpdb;
		$cursor = isset( $state['as_cursor'] ) ? (int) $state['as_cursor'] : 0;
		$limit  = (int) apply_filters( 'mvn_as_scan_chunk_size', self::CHUNK );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from verified schema.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT action_id, hook, status, args, schedule, group_id, attempts, extended_args
				FROM `{$table}`
				ORDER BY action_id ASC
				LIMIT %d OFFSET %d",
				$limit,
				$cursor
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			$state['as_cursor']    = isset( $state['as_total'] ) ? (int) $state['as_total'] : $cursor;
			$state['as_processed'] = (int) $state['as_cursor'];
			$state['processed']    = (int) $state['as_processed'];
			$state['cursor']       = (int) $state['as_cursor'];
			return;
		}

		$group_names = self::resolve_group_names( $rows );

		foreach ( $rows as $row ) {
			$gid = isset( $row['group_id'] ) ? (int) $row['group_id'] : 0;
			$row['group_name'] = isset( $group_names[ $gid ] ) ? $group_names[ $gid ] : '';
			self::scan_action( $row, $state );
		}

		$done = count( $rows );
		$state['as_cursor']    = $cursor + $done;
		$state['as_processed'] = (int) $state['as_cursor'];
		$state['processed']    = (int) $state['as_processed'];
		$state['cursor']       = (int) $state['as_cursor'];
	}

	public static function is_done( $state ) {
		if ( empty( $state['as_available'] ) ) {
			return true;
		}
		$total  = isset( $state['as_total'] ) ? (int) $state['as_total'] : 0;
		$cursor = isset( $state['as_cursor'] ) ? (int) $state['as_cursor'] : 0;
		return $cursor >= $total;
	}

	public static function phase_label() {
		return 'Action Scheduler';
	}

	/* ===================== Standalone ===================== */

	/**
	 * Start a dedicated Action Scheduler scan (outside full scan).
	 *
	 * @return array|WP_Error
	 */
	public static function standalone_start() {
		$meta = self::table_meta();
		if ( ! $meta['available'] ) {
			return new WP_Error(
				'as_missing',
				'جداول Action Scheduler روی این سایت یافت نشد (معمولاً با ووکامرس یا پلاگین Action Scheduler نصب می‌شود).'
			);
		}

		$state = array(
			'id'         => gmdate( 'YmdHis' ) . '-as',
			'mode'       => 'standalone',
			'status'     => 'running',
			'started_at' => gmdate( 'c' ),
			'issues'     => array(),
			'stats'      => array(
				'critical' => 0,
				'warning'  => 0,
				'info'     => 0,
				'as'       => 0,
			),
		);
		self::begin_phase( $state );
		if ( self::is_done( $state ) ) {
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
			self::finalize_standalone( $state );
		}
		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function standalone_tick() {
		$state = mvn_state_read( self::STATE_KEY );
		if ( empty( $state ) || empty( $state['status'] ) || 'running' !== $state['status'] ) {
			return $state;
		}

		self::tick( $state );
		$state['updated_at'] = gmdate( 'c' );

		if ( self::is_done( $state ) ) {
			$state['status']      = 'done';
			$state['finished_at'] = gmdate( 'c' );
			self::finalize_standalone( $state );
			mvn_log( 'Standalone AS scan done: issues=' . count( isset( $state['issues'] ) ? $state['issues'] : array() ) );
		}

		mvn_state_write( self::STATE_KEY, $state );
		return $state;
	}

	public static function get_standalone_state() {
		return mvn_state_read( self::STATE_KEY );
	}

	/**
	 * Table availability for UI.
	 *
	 * @return array{available:bool,count:int,actions:string,logs:string}
	 */
	public static function availability() {
		return self::table_meta();
	}

	/* ===================== Internals ===================== */

	private static function finalize_standalone( &$state ) {
		$issues = isset( $state['issues'] ) ? $state['issues'] : array();
		update_option(
			'mvn_as_scan_last',
			array(
				'finished_at' => gmdate( 'c' ),
				'total'       => isset( $state['as_total'] ) ? (int) $state['as_total'] : 0,
				'issue_count' => count( $issues ),
				'stats'       => isset( $state['stats'] ) ? $state['stats'] : array(),
				'ok'          => ( 0 === count( $issues ) ),
			),
			false
		);
		self::merge_standalone_issues( $state );
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
				$existing[]   = $iss;
				$keys[ $key ] = true;
			}
		}

		update_option( MVN_OPTION_ISSUES, MVN_Scanner::sort_issues( $existing ), false );
	}

	/**
	 * @return array{available:bool,count:int,actions:string,logs:string}
	 */
	private static function table_meta() {
		global $wpdb;

		$actions = $wpdb->prefix . 'actionscheduler_actions';
		$logs    = $wpdb->prefix . 'actionscheduler_logs';
		$like    = $wpdb->esc_like( $actions );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) );
		if ( $exists !== $actions ) {
			return array(
				'available' => false,
				'count'     => 0,
				'actions'   => $actions,
				'logs'      => $logs,
			);
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$actions}`" );

		return array(
			'available' => true,
			'count'     => $count,
			'actions'   => $actions,
			'logs'      => $logs,
		);
	}

	/**
	 * @param array[] $rows
	 * @return array<int,string>
	 */
	private static function resolve_group_names( $rows ) {
		global $wpdb;

		$ids = array();
		foreach ( $rows as $row ) {
			$gid = isset( $row['group_id'] ) ? (int) $row['group_id'] : 0;
			if ( $gid > 0 ) {
				$ids[ $gid ] = true;
			}
		}
		if ( empty( $ids ) ) {
			return array();
		}

		$groups = $wpdb->prefix . 'actionscheduler_groups';
		$like   = $wpdb->esc_like( $groups );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) ) !== $groups ) {
			return array();
		}

		$id_list = implode( ',', array_map( 'intval', array_keys( $ids ) ) );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$map_rows = $wpdb->get_results( "SELECT group_id, slug FROM `{$groups}` WHERE group_id IN ({$id_list})", ARRAY_A );
		$out      = array();
		if ( is_array( $map_rows ) ) {
			foreach ( $map_rows as $g ) {
				$out[ (int) $g['group_id'] ] = isset( $g['slug'] ) ? (string) $g['slug'] : '';
			}
		}
		return $out;
	}

	private static function scan_action( $row, &$state ) {
		$action_id = isset( $row['action_id'] ) ? (int) $row['action_id'] : 0;
		$hook      = isset( $row['hook'] ) ? (string) $row['hook'] : '';
		$status    = isset( $row['status'] ) ? (string) $row['status'] : '';
		$args      = isset( $row['args'] ) ? (string) $row['args'] : '';
		$ext       = isset( $row['extended_args'] ) ? (string) $row['extended_args'] : '';
		$group     = isset( $row['group_name'] ) ? (string) $row['group_name'] : '';
		$payload   = $args . ( '' !== $ext ? "\n" . $ext : '' );

		$max = (int) apply_filters( 'mvn_as_scan_max_value_bytes', 262144 );
		if ( strlen( $payload ) > $max ) {
			$payload = substr( $payload, 0, $max );
		}

		$findings = self::evaluate( $hook, $payload, $group, $status );
		if ( empty( $findings ) ) {
			return;
		}

		$rel  = 'as:actionscheduler_actions:' . $action_id;
		$hash = md5( $hook . '|' . $payload );

		foreach ( $findings as $finding ) {
			$snippet_src = '' !== $payload ? $payload : $hook;
			if ( MVN_Scanner::add_finding(
				$state,
				array(
					'source'    => 'as',
					'table'     => 'actionscheduler_actions',
					'row_id'    => $action_id,
					'column'    => isset( $finding['column'] ) ? $finding['column'] : 'args',
					'hook'      => $hook,
					'as_status' => $status,
					'group'     => $group,
					'rel'       => $rel,
					'sig'       => $finding['id'],
					'label'     => $finding['label'],
					'severity'  => $finding['severity'],
					'detail'    => $finding['detail'],
					'action'    => 'as_delete',
					'clean'     => 'none',
					'snippet'   => self::snippet( $snippet_src, 0, 220 ),
				),
				$payload,
				$hash
			) ) {
				self::bump_stats( $state, $finding['severity'] );
			}
		}
	}

	/**
	 * @return array[] list of {id,label,severity,detail,column}
	 */
	private static function evaluate( $hook, $payload, $group, $status ) {
		$out = array();

		$payload_hit = self::payload_malware_detail( $payload );
		if ( $payload_hit ) {
			$out[] = array(
				'id'       => 'as_payload_malware',
				'label'    => 'کد مخرب در آرگومان Action Scheduler',
				'severity' => 'critical',
				'detail'   => $payload_hit . ' — hook: ' . $hook . ( $status ? " [{$status}]" : '' ),
				'column'   => 'args',
			);
		}

		$hook_hit = self::hook_suspicious_detail( $hook );
		if ( $hook_hit ) {
			// Name-only suspicion without payload → warning; with payload already critical above.
			$severity = $payload_hit ? 'critical' : 'warning';
			$out[]     = array(
				'id'       => 'as_suspicious_hook',
				'label'    => 'hook مشکوک در Action Scheduler',
				'severity' => $severity,
				'detail'   => $hook_hit . ( $status ? " [{$status}]" : '' ),
				'column'   => 'hook',
			);
		}

		$group_hit = self::group_suspicious_detail( $group );
		if ( $group_hit && ( $payload_hit || $hook_hit || self::is_random_token( $group ) ) ) {
			$out[] = array(
				'id'       => 'as_suspicious_group',
				'label'    => 'گروه مشکوک Action Scheduler',
				'severity' => 'warning',
				'detail'   => $group_hit . ' — hook: ' . $hook,
				'column'   => 'group',
			);
		}

		// Unknown / unregistered hook with non-empty weird args (serialized PHP-looking).
		if ( ! $payload_hit && ! $hook_hit && $hook && ! self::is_known_safe_hook( $hook ) ) {
			if ( self::looks_like_executable_blob( $payload ) ) {
				$out[] = array(
					'id'       => 'as_unknown_hook_blob',
					'label'    => 'hook ناشناخته با payload اجرایی',
					'severity' => 'critical',
					'detail'   => 'hook خارج از پیشوندهای رایج با محتوای شبیه کد اجرایی: ' . $hook,
					'column'   => 'args',
				);
			}
		}

		return apply_filters( 'mvn_as_evaluate_findings', $out, $hook, $payload, $group, $status );
	}

	private static function payload_malware_detail( $payload ) {
		if ( '' === $payload || strlen( $payload ) < 8 ) {
			return false;
		}
		if ( preg_match( '/<\?php/i', $payload ) ) {
			return 'تگ PHP داخل args';
		}
		if ( preg_match( '/\b(?:eval|assert|create_function)\s*\(/i', $payload ) ) {
			return 'فراخوانی eval/assert داخل args';
		}
		if ( preg_match( '/\b(?:shell_exec|passthru|system|proc_open|popen|exec)\s*\(/i', $payload ) ) {
			return 'دستور شل داخل args';
		}
		if ( preg_match( '/\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $payload )
			&& preg_match( '/\b(?:eval|assert|create_function|preg_replace)\s*\(/i', $payload ) ) {
			return 'رمزگشایی + اجرا داخل args';
		}
		if ( preg_match( '/preg_replace\s*\([^)]*\/[^\/]*e[^\/]*\//i', $payload ) ) {
			return 'preg_replace /e داخل args';
		}
		if ( preg_match( '/\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\(/i', $payload )
			&& preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\b/', $payload ) ) {
			return 'نوشتن فایل با ورودی کاربر داخل args';
		}
		if ( preg_match( '/O:\d+:"(?:Exception|ReflectionClass|ReflectionFunction|SplFileObject|PDO|Phar)"/i', $payload ) ) {
			return 'شیء سریالایز خطرناک داخل args';
		}
		return false;
	}

	private static function hook_suspicious_detail( $hook ) {
		if ( '' === $hook ) {
			return false;
		}
		if ( preg_match( '/^[a-f0-9]{16,}$/i', $hook ) ) {
			return 'نام hook شبیه هش تصادفی: ' . $hook;
		}
		if ( preg_match( '/(?:shell|backdoor|webshell|c99|r57|malware|eval_payload|wp_hack)/i', $hook ) ) {
			return 'نام hook حاوی کلمات مخرب: ' . $hook;
		}
		if ( preg_match( '/^[A-Za-z0-9+\/=]{40,}$/', $hook ) ) {
			return 'نام hook شبیه base64/obfuscated: ' . substr( $hook, 0, 48 );
		}
		// Short random tokens without namespace separators — common malware AS abuse.
		if ( preg_match( '/^[a-z]{2,6}[0-9]{8,}$/i', $hook ) && ! self::is_known_safe_hook( $hook ) ) {
			return 'نام hook الگوی تصادفی مشکوک: ' . $hook;
		}
		return false;
	}

	private static function group_suspicious_detail( $group ) {
		if ( '' === $group ) {
			return false;
		}
		if ( preg_match( '/^[a-f0-9]{16,}$/i', $group ) ) {
			return 'نام گروه شبیه هش: ' . $group;
		}
		if ( preg_match( '/(?:shell|backdoor|malware|hack)/i', $group ) ) {
			return 'نام گروه مشکوک: ' . $group;
		}
		if ( self::is_random_token( $group ) ) {
			return 'نام گروه تصادفی: ' . $group;
		}
		return false;
	}

	private static function is_random_token( $value ) {
		return (bool) preg_match( '/^[a-f0-9]{16,}$/i', $value );
	}

	private static function looks_like_executable_blob( $payload ) {
		if ( strlen( $payload ) < 40 ) {
			return false;
		}
		if ( preg_match( '/\b(?:base64_decode|gzinflate|strrev|str_rot13)\s*\(/i', $payload ) ) {
			return true;
		}
		if ( preg_match( '/\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}/i', $payload ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Hooks that are commonly legitimate — name-only heuristics are softer for these.
	 */
	private static function is_known_safe_hook( $hook ) {
		$prefixes = apply_filters(
			'mvn_as_safe_hook_prefixes',
			array(
				'woocommerce_',
				'wc_',
				'action_scheduler',
				'as_',
				'wp_',
				'elementor_',
				'jetpack_',
				'yoast_',
				'wpseo_',
				'rank_math',
				'litespeed_',
				'mailpoet_',
				'fluentcrm_',
				'groundhogg_',
				'affwp_',
				'slicewp_',
				'wpml_',
				'icl_',
				'gravityforms',
				'gform_',
				'acf_',
				'pum_',
				'itsec_',
				'wordfence_',
				'wf_',
				'updraft',
				'backupbuddy',
				'ai1wm_',
				'action_scheduler_run_queue',
				'wpforms_',
				'metform_',
				'woodmart_',
				'revslider',
			)
		);
		foreach ( $prefixes as $prefix ) {
			if ( 0 === stripos( $hook, $prefix ) ) {
				return true;
			}
		}
		return (bool) apply_filters( 'mvn_as_is_safe_hook', false, $hook );
	}

	private static function bump_stats( &$state, $severity ) {
		if ( isset( $state['stats'][ $severity ] ) ) {
			$state['stats'][ $severity ]++;
		}
		if ( ! isset( $state['stats']['as'] ) ) {
			$state['stats']['as'] = 0;
		}
		$state['stats']['as']++;
	}

	private static function snippet( $content, $offset, $len ) {
		$start = max( 0, $offset - 40 );
		$chunk = substr( $content, $start, $len );
		$chunk = preg_replace( '/\s+/', ' ', $chunk );
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $chunk, 0, $len );
		}
		return substr( $chunk, 0, $len );
	}

	/**
	 * Delete a suspicious Action Scheduler row (and related logs), after quarantine backup.
	 *
	 * @param array $issue Finding.
	 * @return true|WP_Error
	 */
	public static function delete_action( $issue ) {
		global $wpdb;

		$action_id = isset( $issue['row_id'] ) ? (int) $issue['row_id'] : 0;
		if ( $action_id <= 0 ) {
			return new WP_Error( 'as_bad_id', 'شناسه action نامعتبر است.' );
		}

		$meta = self::table_meta();
		if ( ! $meta['available'] ) {
			return new WP_Error( 'as_missing', 'جدول Action Scheduler موجود نیست.' );
		}

		$table = $meta['actions'];
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT action_id, hook, status, args, schedule, group_id, attempts, extended_args
				FROM `{$table}` WHERE action_id = %d",
				$action_id
			),
			ARRAY_A
		);

		if ( empty( $row ) ) {
			// Already gone — treat as success.
			return true;
		}

		$backup_id = MVN_Quarantine::store_text(
			'as:actionscheduler_actions:' . $action_id,
			wp_json_encode( $row ),
			array(
				'reason' => 'as-action-delete',
				'issue'  => $issue,
			)
		);
		if ( ! $backup_id ) {
			return new WP_Error( 'as_backup_fail', 'پشتیبان‌گیری action قبل از حذف ناموفق بود.' );
		}

		$deleted = $wpdb->delete( $table, array( 'action_id' => $action_id ), array( '%d' ) );
		if ( false === $deleted ) {
			return new WP_Error( 'as_delete_fail', 'حذف action ناموفق بود.' );
		}

		$logs = $meta['logs'];
		$like = $wpdb->esc_like( $logs );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) ) === $logs ) {
			$wpdb->delete( $logs, array( 'action_id' => $action_id ), array( '%d' ) );
		}

		$hook = isset( $row['hook'] ) ? $row['hook'] : '';
		mvn_log( "AS action deleted: id={$action_id} hook={$hook}" );
		return true;
	}

	/**
	 * Wipe all Action Scheduler actions (and related logs/claims).
	 *
	 * Stores a compact quarantine summary (counts + sample rows) before truncate.
	 *
	 * @return array|WP_Error {actions_deleted, logs_deleted, claims_deleted, backup_id, remaining}
	 */
	public static function purge_all_actions() {
		global $wpdb;

		$meta = self::table_meta();
		if ( ! $meta['available'] ) {
			return new WP_Error( 'as_missing', 'جدول Action Scheduler موجود نیست.' );
		}

		$actions_table = $meta['actions'];
		$logs_table    = $meta['logs'];
		$claims_table  = $wpdb->prefix . 'actionscheduler_claims';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$actions_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$actions_table}`" );

		$logs_count = 0;
		$like_logs  = $wpdb->esc_like( $logs_table );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$logs_exist = ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like_logs ) ) === $logs_table );
		if ( $logs_exist ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$logs_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$logs_table}`" );
		}

		$claims_count = 0;
		$like_claims  = $wpdb->esc_like( $claims_table );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$claims_exist = ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like_claims ) ) === $claims_table );
		if ( $claims_exist ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$claims_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$claims_table}`" );
		}

		// Sample rows for quarantine (full dump of huge queues is impractical).
		$sample_limit = (int) apply_filters( 'mvn_as_purge_sample_limit', 200 );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$sample = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT action_id, hook, status, args, schedule, group_id, attempts, extended_args
				FROM `{$actions_table}`
				ORDER BY action_id DESC
				LIMIT %d",
				max( 1, $sample_limit )
			),
			ARRAY_A
		);
		if ( ! is_array( $sample ) ) {
			$sample = array();
		}

		$backup_payload = wp_json_encode(
			array(
				'purged_at'     => gmdate( 'c' ),
				'actions_count' => $actions_count,
				'logs_count'    => $logs_count,
				'claims_count'  => $claims_count,
				'sample_limit'  => $sample_limit,
				'sample'        => $sample,
			)
		);

		$backup_id = MVN_Quarantine::store_text(
			'as:actionscheduler_actions:purge-all',
			$backup_payload,
			array(
				'reason'         => 'as-purge-all',
				'actions_count'  => $actions_count,
				'logs_count'     => $logs_count,
				'claims_count'   => $claims_count,
			)
		);
		if ( ! $backup_id ) {
			return new WP_Error( 'as_backup_fail', 'پشتیبان‌گیری خلاصه قبل از پاکسازی ناموفق بود.' );
		}

		// Prefer TRUNCATE for large queues; fall back to DELETE.
		$actions_ok = self::empty_table( $actions_table );
		if ( ! $actions_ok ) {
			return new WP_Error( 'as_purge_fail', 'پاکسازی جدول actionscheduler_actions ناموفق بود.' );
		}

		$logs_deleted = 0;
		if ( $logs_exist ) {
			self::empty_table( $logs_table );
			$logs_deleted = $logs_count;
		}

		$claims_deleted = 0;
		if ( $claims_exist ) {
			self::empty_table( $claims_table );
			$claims_deleted = $claims_count;
		}

		// Drop related open findings (source=as).
		self::clear_as_findings();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$remaining = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$actions_table}`" );

		mvn_log(
			sprintf(
				'AS purge-all: actions=%d logs=%d claims=%d remaining=%d backup=%s',
				$actions_count,
				$logs_deleted,
				$claims_deleted,
				$remaining,
				$backup_id
			)
		);

		return array(
			'actions_deleted' => $actions_count,
			'logs_deleted'    => $logs_deleted,
			'claims_deleted'  => $claims_deleted,
			'remaining'       => $remaining,
			'backup_id'       => $backup_id,
			'message'         => sprintf(
				'همه actionها پاک شدند: %d مورد (لاگ: %d، claim: %d).',
				$actions_count,
				$logs_deleted,
				$claims_deleted
			),
		);
	}

	/**
	 * TRUNCATE table, or DELETE ALL if truncate fails.
	 *
	 * @param string $table Full table name.
	 * @return bool
	 */
	private static function empty_table( $table ) {
		global $wpdb;

		$table = preg_replace( '/[^a-zA-Z0-9_]/', '', (string) $table );
		if ( '' === $table ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$ok = $wpdb->query( "TRUNCATE TABLE `{$table}`" );
		if ( false !== $ok ) {
			return true;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$ok = $wpdb->query( "DELETE FROM `{$table}`" );
		return ( false !== $ok );
	}

	/**
	 * Remove open AS findings from the issues list after a full purge.
	 */
	private static function clear_as_findings() {
		$issues = MVN_Scanner::get_issues();
		if ( empty( $issues ) || ! is_array( $issues ) ) {
			return;
		}
		$kept = array();
		foreach ( $issues as $iss ) {
			$source = isset( $iss['source'] ) ? $iss['source'] : '';
			$rel    = isset( $iss['rel'] ) ? $iss['rel'] : '';
			if ( 'as' === $source || 0 === strpos( $rel, 'as:' ) ) {
				continue;
			}
			$kept[] = $iss;
		}
		if ( count( $kept ) !== count( $issues ) ) {
			update_option( MVN_OPTION_ISSUES, array_values( $kept ), false );
		}
	}
}
