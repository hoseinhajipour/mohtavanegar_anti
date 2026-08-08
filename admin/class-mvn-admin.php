<?php
/**
 * Admin UI + AJAX handlers.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Admin {

	/** @var MVN_Admin */
	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_init', array( $this, 'maybe_export_issues_csv' ) );
		add_action( 'admin_init', array( $this, 'maybe_export_perf_csv' ) );

		$ajax = array(
			'mvn_scan_start',
			'mvn_scan_tick',
			'mvn_scan_status',
			'mvn_scan_pause',
			'mvn_scan_resume',
			'mvn_scan_stop',
			'mvn_sig_pack_update',
			'mvn_fix_one',
			'mvn_fix_batch',
			'mvn_fix_preview',
			'mvn_fix_deactivate',
			'mvn_fix_clear',
			'mvn_fix_ignore',
			'mvn_htaccess_restore',
			'mvn_htaccess_purge',
			'mvn_uploads_harden',
			'mvn_core_start',
			'mvn_core_tick',
			'mvn_core_download',
			'mvn_core_selective',
			'mvn_core_integrity_start',
			'mvn_core_integrity_tick',
			'mvn_as_scan_start',
			'mvn_as_scan_tick',
			'mvn_as_purge_all',
			'mvn_plugin_start',
			'mvn_plugin_tick',
			'mvn_theme_start',
			'mvn_theme_tick',
			'mvn_perms_start',
			'mvn_perms_tick',
			'mvn_hardening_save',
			'mvn_http_guard_list',
			'mvn_http_guard_block',
			'mvn_http_guard_unblock',
			'mvn_http_guard_add',
			'mvn_http_guard_clear',
			'mvn_quarantine_restore',
			'mvn_quarantine_purge',
			'mvn_quarantine_batch',
			'mvn_perf_arm',
			'mvn_perf_disarm',
			'mvn_perf_optimize',
			'mvn_perf_clear',
		);
		foreach ( $ajax as $action ) {
			add_action( 'wp_ajax_' . $action, array( $this, 'ajax_' . substr( $action, 4 ) ) );
		}
	}

	public function menu() {
		$cap = 'manage_options';
		add_menu_page(
			'آنتی‌ویروس محتوانگار',
			'آنتی‌ویروس',
			$cap,
			'mvn-antivirus',
			array( $this, 'page_dashboard' ),
			'dashicons-shield',
			3
		);
		add_submenu_page( 'mvn-antivirus', 'داشبورد', 'داشبورد', $cap, 'mvn-antivirus', array( $this, 'page_dashboard' ) );
		add_submenu_page( 'mvn-antivirus', 'اسکن', 'اسکن', $cap, 'mvn-scan', array( $this, 'page_scan' ) );
		add_submenu_page( 'mvn-antivirus', 'رفع مشکلات (Fix)', 'رفع مشکلات', $cap, 'mvn-fix', array( $this, 'page_fix' ) );
		add_submenu_page( 'mvn-antivirus', 'تعمیر هسته (Repair)', 'تعمیر هسته', $cap, 'mvn-repair', array( $this, 'page_repair' ) );
		add_submenu_page( 'mvn-antivirus', 'سخت‌سازی', 'سخت‌سازی', $cap, 'mvn-hardening', array( $this, 'page_hardening' ) );
		add_submenu_page( 'mvn-antivirus', 'قرنطینه', 'قرنطینه', $cap, 'mvn-quarantine', array( $this, 'page_quarantine' ) );
		add_submenu_page( 'mvn-antivirus', 'سرعت لود', 'سرعت لود', $cap, 'mvn-perf', array( $this, 'page_perf' ) );
	}

	public function assets( $hook ) {
		if ( false === strpos( $hook, 'mvn-' ) && false === strpos( $hook, 'mvn-antivirus' ) ) {
			return;
		}
		wp_enqueue_style( 'mvn-admin', MVN_PLUGIN_URL . 'assets/admin.css', array(), MVN_VERSION );
		wp_enqueue_script( 'mvn-admin', MVN_PLUGIN_URL . 'assets/admin.js', array( 'jquery' ), MVN_VERSION, true );
		wp_localize_script(
			'mvn-admin',
			'MVN',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( MVN_NONCE_ACTION ),
				'i18n'  => array(
					'scanning'       => 'در حال اسکن...',
					'paused'         => 'اسکن متوقف موقت شد',
					'stopped'        => 'اسکن متوقف شد',
					'done'           => 'تمام شد',
					'error'          => 'خطا',
					'confirm'        => 'آیا مطمئن هستید؟',
					'confirm_stop'   => 'اسکن همین‌جا متوقف شود؟ یافته‌های فعلی ذخیره می‌مانند.',
					'confirm_ignore' => 'این مورد به عنوان امن علامت‌گذاری شود و در اسکن‌های بعدی نادیده گرفته شود؟',
					'fixing'         => 'در حال رفع...',
					'repairing'      => 'در حال تعمیر...',
					'ignoring'       => 'در حال ثبت...',
					'ignored'        => 'امن علامت‌گذاری شد.',
				),
			)
		);
	}

	private function render( $view, $vars = array() ) {
		$file = MVN_PLUGIN_DIR . 'admin/views/' . $view . '.php';
		if ( ! is_file( $file ) ) {
			echo '<div class="wrap"><p>View missing.</p></div>';
			return;
		}
		extract( $vars, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract
		include MVN_PLUGIN_DIR . 'admin/views/_layout-top.php';
		include $file;
		include MVN_PLUGIN_DIR . 'admin/views/_layout-bottom.php';
	}

	public function page_dashboard() {
		$last   = get_option( MVN_OPTION_LASTSCAN, array() );
		$issues = MVN_Scanner::get_issues();
		$ht     = MVN_Htaccess_Guard::root_status();
		$core   = MVN_Core_Repair::source_status();
		$hard   = MVN_Hardening::instance()->settings();
		$this->render(
			'dashboard',
			array(
				'last'      => $last,
				'issues'    => $issues,
				'ht'        => $ht,
				'core'      => $core,
				'hard'      => $hard,
				'sig_pack'  => MVN_Signature_Pack::status(),
				'q_count'   => count( MVN_Quarantine::list_all() ),
				'checklist' => mvn_security_checklist(
					array(
						'last'      => $last,
						'issues'    => $issues,
						'ht'        => $ht,
						'core'      => $core,
						'hard'      => $hard,
						'integrity' => MVN_Core_Integrity::last_summary(),
						'perms'     => MVN_Permissions::get_state(),
					)
				),
			)
		);
	}

	public function page_scan() {
		$this->render(
			'scan',
			array(
				'state'      => MVN_Scanner::get_state(),
				'sig_pack'   => MVN_Signature_Pack::status(),
				'as_meta'    => MVN_AS_Scanner::availability(),
				'as_state'   => MVN_AS_Scanner::get_standalone_state(),
			)
		);
	}

	public function page_fix() {
		$issues = MVN_Scanner::get_issues();
		$this->render(
			'fix',
			array(
				'issues'       => $issues,
				'action_counts' => MVN_Scanner::count_by_action( $issues ),
				'export_url'   => wp_nonce_url(
					admin_url( 'admin.php?page=mvn-fix&mvn_export=csv' ),
					'mvn_export_issues_csv',
					'nonce'
				),
			)
		);
	}

	/**
	 * Download open issues as CSV (fix page export).
	 */
	public function maybe_export_issues_csv() {
		if ( ! isset( $_GET['page'] ) || 'mvn-fix' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ) {
			return;
		}
		if ( empty( $_GET['mvn_export'] ) || 'csv' !== sanitize_key( wp_unslash( $_GET['mvn_export'] ) ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'دسترسی ندارید.', 'mvn' ), 403 );
		}
		check_admin_referer( 'mvn_export_issues_csv', 'nonce' );

		$csv      = MVN_Scanner::issues_to_csv();
		$filename = 'mvn-issues-' . gmdate( 'Y-m-d-His' ) . '.csv';

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . strlen( $csv ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $csv;
		exit;
	}

	/**
	 * Download last perf report as CSV.
	 */
	public function maybe_export_perf_csv() {
		if ( ! isset( $_GET['page'] ) || 'mvn-perf' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ) {
			return;
		}
		if ( empty( $_GET['mvn_export'] ) || 'csv' !== sanitize_key( wp_unslash( $_GET['mvn_export'] ) ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'دسترسی ندارید.', 'mvn' ), 403 );
		}
		check_admin_referer( 'mvn_export_perf_csv', 'nonce' );

		$csv      = MVN_Perf::report_to_csv();
		$filename = 'mvn-perf-' . gmdate( 'Y-m-d-His' ) . '.csv';

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . strlen( $csv ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $csv;
		exit;
	}

	public function page_repair() {
		$this->render(
			'repair',
			array(
				'core'       => MVN_Core_Repair::source_status(),
				'ht'         => MVN_Htaccess_Guard::root_status(),
				'uploads_ht' => MVN_Htaccess_Guard::uploads_status(),
				'cstate'     => MVN_Core_Repair::get_state(),
				'istate'     => MVN_Core_Integrity::get_standalone_state(),
				'integrity'  => MVN_Core_Integrity::last_summary(),
				'pstate'     => MVN_Permissions::get_state(),
				'plugins'    => MVN_Plugin_Repair::catalog_status(),
				'themes'     => MVN_Theme_Repair::catalog_status(),
				'plstate'    => MVN_Plugin_Repair::get_state(),
				'thstate'    => MVN_Theme_Repair::get_state(),
			)
		);
	}

	public function page_hardening() {
		$this->render(
			'hardening',
			array(
				'settings'   => MVN_Hardening::instance()->settings(),
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function page_quarantine() {
		$this->render(
			'quarantine',
			array(
				'items' => MVN_Quarantine::list_all(),
			)
		);
	}

	public function page_perf() {
		$this->render(
			'perf',
			array(
				'arm'        => MVN_Perf::arm_status(),
				'report'     => MVN_Perf::last_report(),
				'blocked'    => MVN_Perf::blocked_hosts(),
				'export_url' => wp_nonce_url(
					admin_url( 'admin.php?page=mvn-perf&mvn_export=csv' ),
					'mvn_export_perf_csv',
					'nonce'
				),
			)
		);
	}

	/* ===================== AJAX ===================== */

	private function guard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'دسترسی ندارید.' ), 403 );
		}
		check_ajax_referer( MVN_NONCE_ACTION, 'nonce' );
	}

	public function ajax_scan_start() {
		$this->guard();
		$scope = isset( $_POST['scope'] ) ? sanitize_key( wp_unslash( $_POST['scope'] ) ) : 'all';
		$deep  = ! empty( $_POST['deep'] );
		$full  = ! empty( $_POST['full'] );
		$scan_db = ! isset( $_POST['scan_db'] ) || ! empty( $_POST['scan_db'] );
		$scan_as = ! isset( $_POST['scan_as'] ) || ! empty( $_POST['scan_as'] );
		$scan_core = ! isset( $_POST['scan_core'] ) || ! empty( $_POST['scan_core'] );
		$scan_repo = ! isset( $_POST['scan_repo'] ) || ! empty( $_POST['scan_repo'] );
		$scan_media = ! isset( $_POST['scan_media'] ) || ! empty( $_POST['scan_media'] );
		$incremental = ! $full && ( ! isset( $_POST['incremental'] ) || ! empty( $_POST['incremental'] ) );
		if ( ! in_array( $scope, array( 'all', 'wp-content', 'core' ), true ) ) {
			$scope = 'all';
		}
		@set_time_limit( 120 );
		$state = MVN_Scanner::start(
			array(
				'scope'       => $scope,
				'deep'        => $deep,
				'incremental' => $incremental,
				'full'        => $full,
				'scan_db'     => $scan_db,
				'scan_as'     => $scan_as,
				'scan_core'   => $scan_core,
				'scan_repo'   => $scan_repo,
				'scan_media'  => $scan_media,
			)
		);
		wp_send_json_success( $this->public_scan_state( $state ) );
	}

	public function ajax_scan_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Scanner::tick();
		wp_send_json_success( $this->public_scan_state( $state ) );
	}

	public function ajax_scan_status() {
		$this->guard();
		wp_send_json_success( $this->public_scan_state( MVN_Scanner::get_state() ) );
	}

	public function ajax_sig_pack_update() {
		$this->guard();
		@set_time_limit( 120 );
		$result = MVN_Signature_Pack::update();
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'message'  => isset( $result['last_message'] ) && $result['last_message']
					? $result['last_message']
					: 'بسته امضا به‌روز شد.',
				'sig_pack' => $result,
			)
		);
	}

	public function ajax_scan_pause() {
		$this->guard();
		$state = MVN_Scanner::pause();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_scan_state( $state ) );
	}

	public function ajax_scan_resume() {
		$this->guard();
		$state = MVN_Scanner::resume();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_scan_state( $state ) );
	}

	public function ajax_scan_stop() {
		$this->guard();
		$state = MVN_Scanner::stop();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_scan_state( $state ) );
	}

	private function public_scan_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		return array(
			'status'            => isset( $state['status'] ) ? $state['status'] : 'idle',
			'total'             => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'processed'         => isset( $state['processed'] ) ? (int) $state['processed'] : 0,
			'catalog'           => isset( $state['catalog'] ) ? (int) $state['catalog'] : ( isset( $state['total'] ) ? (int) $state['total'] : 0 ),
			'skipped_unchanged' => isset( $state['skipped_unchanged'] ) ? (int) $state['skipped_unchanged'] : 0,
			'incremental'       => ! empty( $state['incremental'] ),
			'scan_db'           => ! empty( $state['scan_db'] ),
			'scan_as'           => ! empty( $state['scan_as'] ),
			'scan_core'         => ! empty( $state['scan_core'] ),
			'scan_repo'         => ! empty( $state['scan_repo'] ),
			'phase'             => isset( $state['phase'] ) ? $state['phase'] : 'files',
			'core_source'       => isset( $state['core_source'] ) ? $state['core_source'] : '',
			'core_version'      => isset( $state['core_version'] ) ? $state['core_version'] : '',
			'repo_label'        => isset( $state['repo_label'] ) ? $state['repo_label'] : '',
			'db_phase'          => isset( $state['db_phase'] ) ? $state['db_phase'] : '',
			'db_phase_label'    => ! empty( $state['db_phase'] ) ? MVN_DB_Scanner::sub_phase_label( $state['db_phase'] ) : '',
			'as_available'      => ! empty( $state['as_available'] ),
			'stats'             => isset( $state['stats'] ) ? $state['stats'] : array(),
			'issue_count'       => isset( $state['issues'] ) ? count( $state['issues'] ) : 0,
			'started_at'        => isset( $state['started_at'] ) ? $state['started_at'] : '',
			'finished_at'       => isset( $state['finished_at'] ) ? $state['finished_at'] : '',
		);
	}

	public function ajax_fix_one() {
		$this->guard();
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => 'شناسه خالی است.' ) );
		}
		$r = MVN_Cleaner::fix_issue( $id );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success( array( 'message' => 'رفع شد.', 'remaining' => count( MVN_Scanner::get_issues() ) ) );
	}

	public function ajax_fix_preview() {
		$this->guard();
		$filter = isset( $_POST['filter'] ) ? sanitize_key( wp_unslash( $_POST['filter'] ) ) : 'safe';
		$id     = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		$allowed = array( '', 'safe', 'all', 'clean', 'delete_htaccess', 'quarantine_delete', 'quarantine', 'db_clean', 'db_delete_option', 'db_review', 'as_delete', 'core_repair_file', 'delete_core_extra', 'repo_repair', 'manual_review' );
		if ( ! in_array( $filter, $allowed, true ) ) {
			$filter = 'safe';
		}
		$plugins = MVN_Cleaner::affected_active_plugins( $filter, $id ? $id : null );
		wp_send_json_success(
			array(
				'plugins' => $plugins,
				'count'   => count( $plugins ),
			)
		);
	}

	public function ajax_fix_deactivate() {
		$this->guard();
		$raw = isset( $_POST['plugins'] ) ? wp_unslash( $_POST['plugins'] ) : array();
		if ( is_string( $raw ) ) {
			$decoded = json_decode( $raw, true );
			$raw     = is_array( $decoded ) ? $decoded : array_filter( array_map( 'trim', explode( ',', $raw ) ) );
		}
		$files = array();
		foreach ( (array) $raw as $file ) {
			$file = sanitize_text_field( $file );
			if ( $file ) {
				$files[] = $file;
			}
		}
		if ( empty( $files ) ) {
			wp_send_json_error( array( 'message' => 'لیست پلاگین خالی است.' ) );
		}
		$result = MVN_Cleaner::deactivate_plugins( $files );
		$msg    = count( $result['deactivated'] ) . ' پلاگین غیرفعال شد.';
		if ( ! empty( $result['failed'] ) ) {
			$msg .= ' خطا: ' . implode( ' | ', $result['failed'] );
		}
		wp_send_json_success(
			array(
				'message' => $msg,
				'result'  => $result,
			)
		);
	}

	public function ajax_fix_batch() {
		$this->guard();
		$filter = isset( $_POST['filter'] ) ? sanitize_key( wp_unslash( $_POST['filter'] ) ) : 'safe';
		$allowed = array( '', 'safe', 'all', 'clean', 'delete_htaccess', 'quarantine_delete', 'quarantine', 'db_clean', 'db_delete_option', 'db_review', 'as_delete', 'core_repair_file', 'delete_core_extra', 'repo_repair', 'manual_review' );
		if ( ! in_array( $filter, $allowed, true ) ) {
			$filter = 'safe';
		}
		@set_time_limit( 120 );
		$result = MVN_Cleaner::fix_batch( $filter, 15 );
		wp_send_json_success( $result );
	}

	public function ajax_fix_clear() {
		$this->guard();
		MVN_Scanner::clear_issues();
		wp_send_json_success( array( 'message' => 'لیست مشکلات پاک شد. یک اسکن جدید اجرا کنید.' ) );
	}

	public function ajax_fix_ignore() {
		$this->guard();
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => 'شناسه خالی است.' ) );
		}
		$permanent = ! empty( $_POST['permanent'] );
		$r         = MVN_Scanner::ignore_issue( $id, $permanent );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'message'   => 'به عنوان امن علامت‌گذاری شد.',
				'remaining' => count( MVN_Scanner::get_issues() ),
			)
		);
	}

	public function ajax_htaccess_restore() {
		$this->guard();
		$r = MVN_Htaccess_Guard::restore_root();
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success( array( 'message' => 'htaccess ریشه بازیابی شد.', 'status' => MVN_Htaccess_Guard::root_status() ) );
	}

	public function ajax_htaccess_purge() {
		$this->guard();
		$aggressive = ! empty( $_POST['aggressive'] );
		$result     = MVN_Htaccess_Guard::purge_rogue( $aggressive );
		wp_send_json_success( $result );
	}

	public function ajax_uploads_harden() {
		$this->guard();
		$result = MVN_Htaccess_Guard::harden_uploads();
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$msg = 'محافظت uploads اعمال شد.';
		if ( ! empty( $result['matched'] ) ) {
			$msg = 'htaccess آپلود از قبل امن بود.';
		} elseif ( ! empty( $result['created'] ) ) {
			$msg = 'فایل deny-PHP در uploads ایجاد شد.';
		} elseif ( ! empty( $result['updated'] ) ) {
			$msg = 'htaccess آپلود به‌روز و امن شد.';
		}
		wp_send_json_success(
			array(
				'message' => $msg,
				'status'  => MVN_Htaccess_Guard::uploads_status(),
			)
		);
	}

	public function ajax_core_start() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Core_Repair::start();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_core_state( $state ) );
	}

	public function ajax_core_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Core_Repair::tick();
		wp_send_json_success( $this->public_core_state( $state ) );
	}

	public function ajax_core_selective() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Core_Repair::start_from_issues();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_core_state( $state ) );
	}

	public function ajax_core_download() {
		$this->guard();
		@set_time_limit( 600 );
		$status = MVN_Core_Repair::download_latest();
		if ( is_wp_error( $status ) ) {
			wp_send_json_error( array( 'message' => $status->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'message' => ! empty( $status['version'] )
					? sprintf( 'آخرین وردپرس (نسخه %s) دریافت و جایگزین شد.', $status['version'] )
					: 'آخرین وردپرس دریافت و جایگزین شد.',
				'core'    => $status,
			)
		);
	}

	private function public_core_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		return array(
			'status'   => isset( $state['status'] ) ? $state['status'] : 'idle',
			'total'    => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'cursor'   => isset( $state['cursor'] ) ? (int) $state['cursor'] : 0,
			'written'  => isset( $state['written'] ) ? (int) $state['written'] : 0,
			'skipped'  => isset( $state['skipped'] ) ? (int) $state['skipped'] : 0,
			'errors'   => isset( $state['errors'] ) ? array_slice( $state['errors'], -10 ) : array(),
		);
	}

	public function ajax_core_integrity_start() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Core_Integrity::standalone_start();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_core_integrity_state( $state ) );
	}

	public function ajax_core_integrity_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Core_Integrity::standalone_tick();
		wp_send_json_success( $this->public_core_integrity_state( $state ) );
	}

	public function ajax_as_scan_start() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_AS_Scanner::standalone_start();
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_as_scan_state( $state ) );
	}

	public function ajax_as_scan_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_AS_Scanner::standalone_tick();
		wp_send_json_success( $this->public_as_scan_state( $state ) );
	}

	public function ajax_as_purge_all() {
		$this->guard();
		@set_time_limit( 300 );
		$result = MVN_AS_Scanner::purge_all_actions();
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$meta = MVN_AS_Scanner::availability();
		$result['count'] = isset( $meta['count'] ) ? (int) $meta['count'] : 0;
		wp_send_json_success( $result );
	}

	private function public_as_scan_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		return array(
			'status'       => isset( $state['status'] ) ? $state['status'] : 'idle',
			'total'        => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'processed'    => isset( $state['processed'] ) ? (int) $state['processed'] : 0,
			'as_available' => ! empty( $state['as_available'] ),
			'issue_count'  => isset( $state['issues'] ) ? count( $state['issues'] ) : 0,
			'stats'        => isset( $state['stats'] ) ? $state['stats'] : array(),
			'started_at'   => isset( $state['started_at'] ) ? $state['started_at'] : '',
			'finished_at'  => isset( $state['finished_at'] ) ? $state['finished_at'] : '',
		);
	}

	private function public_core_integrity_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		$issue_count = isset( $state['issues'] ) ? count( $state['issues'] ) : 0;
		return array(
			'status'       => isset( $state['status'] ) ? $state['status'] : 'idle',
			'total'        => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'processed'    => isset( $state['processed'] ) ? (int) $state['processed'] : 0,
			'core_sub'     => isset( $state['core_sub'] ) ? $state['core_sub'] : '',
			'core_source'  => isset( $state['core_source'] ) ? $state['core_source'] : '',
			'core_version' => isset( $state['core_version'] ) ? $state['core_version'] : '',
			'issue_count'  => $issue_count,
			'stats'        => isset( $state['stats'] ) ? $state['stats'] : array(),
		);
	}

	public function ajax_plugin_start() {
		$this->guard();
		$slug = isset( $_POST['slug'] ) ? sanitize_key( wp_unslash( $_POST['slug'] ) ) : '';
		if ( ! $slug ) {
			wp_send_json_error( array( 'message' => 'slug خالی است.' ) );
		}
		@set_time_limit( 300 );
		$state = MVN_Plugin_Repair::start( $slug );
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_plugin_state( $state ) );
	}

	public function ajax_plugin_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Plugin_Repair::tick();
		wp_send_json_success( $this->public_plugin_state( $state ) );
	}

	public function ajax_theme_start() {
		$this->guard();
		$slug = isset( $_POST['slug'] ) ? sanitize_title( wp_unslash( $_POST['slug'] ) ) : '';
		if ( ! $slug ) {
			wp_send_json_error( array( 'message' => 'slug قالب خالی است.' ) );
		}
		@set_time_limit( 300 );
		$state = MVN_Theme_Repair::start( $slug );
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $this->public_theme_state( $state ) );
	}

	public function ajax_theme_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Theme_Repair::tick();
		wp_send_json_success( $this->public_theme_state( $state ) );
	}

	private function public_theme_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		return array(
			'status'  => isset( $state['status'] ) ? $state['status'] : 'idle',
			'slug'    => isset( $state['slug'] ) ? $state['slug'] : '',
			'name'    => isset( $state['name'] ) ? $state['name'] : '',
			'total'   => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'cursor'  => isset( $state['cursor'] ) ? (int) $state['cursor'] : 0,
			'written' => isset( $state['written'] ) ? (int) $state['written'] : 0,
			'skipped' => isset( $state['skipped'] ) ? (int) $state['skipped'] : 0,
			'errors'  => isset( $state['errors'] ) ? array_slice( $state['errors'], -10 ) : array(),
		);
	}

	private function public_plugin_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		return array(
			'status'  => isset( $state['status'] ) ? $state['status'] : 'idle',
			'slug'    => isset( $state['slug'] ) ? $state['slug'] : '',
			'name'    => isset( $state['name'] ) ? $state['name'] : '',
			'folder'  => isset( $state['folder'] ) ? $state['folder'] : '',
			'total'   => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'cursor'  => isset( $state['cursor'] ) ? (int) $state['cursor'] : 0,
			'written' => isset( $state['written'] ) ? (int) $state['written'] : 0,
			'skipped' => isset( $state['skipped'] ) ? (int) $state['skipped'] : 0,
			'errors'  => isset( $state['errors'] ) ? array_slice( $state['errors'], -10 ) : array(),
			'backup'  => isset( $state['backup_path'] ) ? $state['backup_path'] : '',
		);
	}

	public function ajax_perms_start() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Permissions::start();
		wp_send_json_success( $this->public_perms_state( $state ) );
	}

	public function ajax_perms_tick() {
		$this->guard();
		@set_time_limit( 120 );
		$state = MVN_Permissions::tick();
		wp_send_json_success( $this->public_perms_state( $state ) );
	}

	private function public_perms_state( $state ) {
		if ( empty( $state ) ) {
			return array( 'status' => 'idle' );
		}
		return array(
			'status'  => isset( $state['status'] ) ? $state['status'] : 'idle',
			'total'   => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'cursor'  => isset( $state['cursor'] ) ? (int) $state['cursor'] : 0,
			'fixed'   => isset( $state['fixed'] ) ? (int) $state['fixed'] : 0,
			'skipped' => isset( $state['skipped'] ) ? (int) $state['skipped'] : 0,
			'errors'  => isset( $state['errors'] ) ? array_slice( $state['errors'], -10 ) : array(),
		);
	}

	public function ajax_hardening_save() {
		$this->guard();
		$raw = isset( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : array(); // phpcs:ignore
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$saved = MVN_Hardening::instance()->save( $raw );
		wp_send_json_success(
			array(
				'message'    => 'تنظیمات ذخیره شد.',
				'settings'   => $saved,
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function ajax_http_guard_list() {
		$this->guard();
		wp_send_json_success(
			array(
				'message'    => 'فهرست بروزرسانی شد.',
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function ajax_http_guard_block() {
		$this->guard();
		$host = isset( $_POST['host'] ) ? sanitize_text_field( wp_unslash( $_POST['host'] ) ) : '';
		$r    = MVN_Http_Guard::block_host( $host );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'message'    => 'دامنه مسدود شد.',
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function ajax_http_guard_unblock() {
		$this->guard();
		$host = isset( $_POST['host'] ) ? sanitize_text_field( wp_unslash( $_POST['host'] ) ) : '';
		$r    = MVN_Http_Guard::unblock_host( $host );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'message'    => 'دامنه مجاز شد.',
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function ajax_http_guard_add() {
		$this->guard();
		$host  = isset( $_POST['host'] ) ? sanitize_text_field( wp_unslash( $_POST['host'] ) ) : '';
		$block = ! empty( $_POST['block'] );
		$r     = MVN_Http_Guard::add_host( $host, $block );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'message'    => $block ? 'دامنه اضافه و مسدود شد.' : 'دامنه به فهرست اضافه شد.',
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function ajax_http_guard_clear() {
		$this->guard();
		MVN_Http_Guard::clear_log();
		wp_send_json_success(
			array(
				'message'    => 'لاگ درخواست‌ها پاک شد.',
				'http_guard' => MVN_Http_Guard::admin_payload(),
			)
		);
	}

	public function ajax_quarantine_restore() {
		$this->guard();
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		$r  = MVN_Quarantine::restore( $id );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success( array( 'message' => 'بازیابی شد.' ) );
	}

	public function ajax_quarantine_purge() {
		$this->guard();
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		$ok = MVN_Quarantine::purge( $id );
		if ( ! $ok ) {
			wp_send_json_error( array( 'message' => 'حذف ناموفق بود.' ) );
		}
		wp_send_json_success( array( 'message' => 'حذف شد.' ) );
	}

	public function ajax_quarantine_batch() {
		$this->guard();
		$action = isset( $_POST['batch_action'] ) ? sanitize_key( wp_unslash( $_POST['batch_action'] ) ) : '';
		if ( ! in_array( $action, array( 'restore', 'purge' ), true ) ) {
			wp_send_json_error( array( 'message' => 'عملیات نامعتبر.' ) );
		}
		$ids = isset( $_POST['ids'] ) ? wp_unslash( $_POST['ids'] ) : array(); // phpcs:ignore
		if ( ! is_array( $ids ) ) {
			$ids = array( $ids );
		}
		$ids = array_values(
			array_filter(
				array_map(
					function ( $id ) {
						return sanitize_text_field( (string) $id );
					},
					$ids
				)
			)
		);
		if ( empty( $ids ) ) {
			wp_send_json_error( array( 'message' => 'هیچ آیتمی انتخاب نشده.' ) );
		}
		@set_time_limit( 120 );
		$result = MVN_Quarantine::batch( $ids, $action, 15 );
		wp_send_json_success( $result );
	}

	public function ajax_perf_arm() {
		$this->guard();
		MVN_Perf::arm( 10, 5 );
		wp_send_json_success(
			array(
				'message' => 'رهگیری فعال شد. صفحه اصلی سایت را باز کنید، سپس این صفحه را تازه کنید.',
				'arm'     => MVN_Perf::arm_status(),
			)
		);
	}

	public function ajax_perf_disarm() {
		$this->guard();
		MVN_Perf::disarm();
		wp_send_json_success(
			array(
				'message' => 'رهگیری متوقف شد.',
				'arm'     => MVN_Perf::arm_status(),
			)
		);
	}

	public function ajax_perf_optimize() {
		$this->guard();
		@set_time_limit( 120 );
		$result = MVN_Perf::optimize();
		wp_send_json_success( $result );
	}

	public function ajax_perf_clear() {
		$this->guard();
		MVN_Perf::clear_report();
		wp_send_json_success( array( 'message' => 'گزارش پاک شد.' ) );
	}
}
