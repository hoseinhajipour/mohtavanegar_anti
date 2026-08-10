<?php
/**
 * Plugin Name:       Mohtavanegar Antivirus
 * Plugin URI:        https://mohtavanegar.local/
 * Description:       آنتی‌ویروس وردپرس: اسکن بدافزار، حذف کدهای تزریق‌شده، تعمیر فایل‌های هسته از سورس سالم، بازیابی htaccess، حذف htaccess های جعلی، سخت‌سازی امنیتی (Brute Force، XMLRPC، سطح دسترسی‌ها).
 * Version:           2.2.4
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Mohtavanegar Security
 * License:           GPLv2 or later
 * Text Domain:       mvn
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MVN_VERSION', '2.2.4' );
define( 'MVN_PLUGIN_FILE', __FILE__ );
define( 'MVN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'MVN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'MVN_SOURCE_ZIP', MVN_PLUGIN_DIR . 'sources/wordpress_core.zip' );
define( 'MVN_SOURCE_HTACCESS', MVN_PLUGIN_DIR . 'sources/default.htaccess' );
define( 'MVN_OPTION_ISSUES', 'mvn_scan_issues' );
define( 'MVN_OPTION_HARDENING', 'mvn_hardening' );
define( 'MVN_OPTION_LASTSCAN', 'mvn_last_scan' );
define( 'MVN_NONCE_ACTION', 'mvn_ajax_nonce' );
if ( ! defined( 'MVN_SIGNATURE_PACK_URL' ) ) {
	define( 'MVN_SIGNATURE_PACK_URL', '' );
}

/**
 * Lightweight always-on includes (front-end safe).
 */
require_once MVN_PLUGIN_DIR . 'includes/helpers.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-url-trust.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-log.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-hardening.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-cloak.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-http-guard.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-perf.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-scheduler.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-file-hash-store.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-incidents.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-reinfection-monitor.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-path-blocker.php';

/**
 * Heavy scan/repair stack — load only in admin, AJAX, cron, or WP-CLI.
 */
function mvn_load_engine() {
	static $loaded = false;
	if ( $loaded ) {
		return;
	}
	$loaded = true;

	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-signature-pack.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-self-integrity.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-audit-log.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-notify.php';
	require_once MVN_PLUGIN_DIR . 'includes/signatures.php';
	require_once MVN_PLUGIN_DIR . 'includes/confidence.php';
	require_once MVN_PLUGIN_DIR . 'includes/signatures-db.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-file-index.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-behavior-scanner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-wpconfig-audit.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-archive-scanner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-local-baseline.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-ignore-list.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-db-scanner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-as-scanner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-core-integrity.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-dropin-audit.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-ghost-plugins.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-repo-integrity.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-quarantine.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-xdav-signatures.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-persistence-scanner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-remediation.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-scanner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-cleaner.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-htaccess-guard.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-core-repair.php';
	require_once MVN_PLUGIN_DIR . 'includes/repo-plugins.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-plugin-repair.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-theme-repair.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-permissions.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-logger.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-rule.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-gateway.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-validator.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-rollback.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-security-migration.php';
	require_once MVN_PLUGIN_DIR . 'includes/class-mvn-cli.php';
}

register_activation_hook( __FILE__, 'mvn_activate' );
register_deactivation_hook( __FILE__, 'mvn_deactivate' );

function mvn_activate() {
	mvn_load_engine();
	mvn_ensure_data_dirs();
	mvn_harden_quarantine_htaccess();
	mvn_install_capabilities();
	if ( false === get_option( MVN_OPTION_HARDENING ) ) {
		add_option( MVN_OPTION_HARDENING, MVN_Hardening::defaults() );
	}
	// Background scans stay off unless admin enables them (site performance).
	update_option( MVN_Scheduler::OPTION, 0, false );
	MVN_Scheduler::deactivate();
	MVN_Signature_Pack::install_from_bundled();
}

function mvn_harden_quarantine_htaccess() {
	$dir = mvn_data_dir() . '/quarantine';
	if ( ! is_dir( $dir ) ) {
		wp_mkdir_p( $dir );
	}
	$ht = "# BEGIN MVN Quarantine\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n<IfModule mod_php.c>\nphp_flag engine off\n</IfModule>\n# END MVN Quarantine\n";
	@file_put_contents( $dir . '/.htaccess', $ht );
}

function mvn_install_capabilities() {
	$role = get_role( 'administrator' );
	if ( $role ) {
		foreach ( array( 'mvn_scan', 'mvn_remediate', 'mvn_configure' ) as $cap ) {
			$role->add_cap( $cap );
		}
	}
}

function mvn_deactivate() {
	MVN_Perf::disarm();
	MVN_Scheduler::deactivate();
	MVN_Reinfection_Monitor::deactivate();
}

MVN_Hardening::instance()->boot();
MVN_Cloak::instance()->boot();
MVN_Http_Guard::instance()->boot();
MVN_Perf::instance()->boot();
MVN_Scheduler::boot();
MVN_Reinfection_Monitor::boot();
MVN_Path_Blocker::boot();

$mvn_need_engine = is_admin()
	|| wp_doing_ajax()
	|| wp_doing_cron()
	|| ( defined( 'WP_CLI' ) && WP_CLI )
	|| ( defined( 'REST_REQUEST' ) && REST_REQUEST );

if ( $mvn_need_engine ) {
	mvn_load_engine();
}

// One-time upgrade tasks (also clears aggressive legacy schedules).
$mvn_installed_ver = get_option( 'mvn_plugin_version', '' );
if ( $mvn_installed_ver !== MVN_VERSION ) {
	mvn_load_engine();
	mvn_install_capabilities();
	mvn_harden_quarantine_htaccess();
	MVN_Signature_Pack::install_from_bundled();
	// Stop legacy 15s scan workers that were slowing the site.
	update_option( MVN_Scheduler::OPTION, 0, false );
	MVN_Scheduler::deactivate();
	if ( class_exists( 'MVN_Path_Blocker', false ) ) {
		update_option( MVN_Path_Blocker::OPTION_ENABLED, 1, false );
		MVN_Path_Blocker::enforce();
	}
	update_option( 'mvn_plugin_version', MVN_VERSION, false );
	mvn_log( 'Upgraded to ' . MVN_VERSION . ' — path blocker on; background schedule off.' );
}

if ( is_admin() ) {
	require_once MVN_PLUGIN_DIR . 'admin/class-mvn-admin.php';
	MVN_Admin::instance()->boot();
}
