<?php
/**
 * Plugin Name:       Mohtavanegar Antivirus
 * Plugin URI:        https://mohtavanegar.local/
 * Description:       آنتی‌ویروس وردپرس: اسکن بدافزار، حذف کدهای تزریق‌شده، تعمیر فایل‌های هسته از سورس سالم، بازیابی htaccess، حذف htaccess های جعلی، سخت‌سازی امنیتی (Brute Force، XMLRPC، سطح دسترسی‌ها).
 * Version:           2.0.1
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Mohtavanegar Security
 * License:           GPLv2 or later
 * Text Domain:       mvn
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MVN_VERSION', '2.0.1' );
define( 'MVN_PLUGIN_FILE', __FILE__ );
define( 'MVN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'MVN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'MVN_SOURCE_ZIP', MVN_PLUGIN_DIR . 'sources/wordpress_core.zip' );
define( 'MVN_SOURCE_HTACCESS', MVN_PLUGIN_DIR . 'sources/default.htaccess' );
define( 'MVN_OPTION_ISSUES', 'mvn_scan_issues' );
define( 'MVN_OPTION_HARDENING', 'mvn_hardening' );
define( 'MVN_OPTION_LASTSCAN', 'mvn_last_scan' );
define( 'MVN_NONCE_ACTION', 'mvn_ajax_nonce' );
// Optional remote signature pack URL (filterable via mvn_signature_pack_url).
if ( ! defined( 'MVN_SIGNATURE_PACK_URL' ) ) {
	define( 'MVN_SIGNATURE_PACK_URL', '' );
}

require_once MVN_PLUGIN_DIR . 'includes/helpers.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-url-trust.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-signature-pack.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-self-integrity.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-incidents.php';
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
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-scanner.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-cleaner.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-htaccess-guard.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-core-repair.php';
require_once MVN_PLUGIN_DIR . 'includes/repo-plugins.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-plugin-repair.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-theme-repair.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-permissions.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-hardening.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-http-guard.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-perf.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-scheduler.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-cli.php';

register_activation_hook( __FILE__, 'mvn_activate' );
register_deactivation_hook( __FILE__, 'mvn_deactivate' );

function mvn_activate() {
	mvn_ensure_data_dirs();
	mvn_install_capabilities();
	if ( false === get_option( MVN_OPTION_HARDENING ) ) {
		add_option( MVN_OPTION_HARDENING, MVN_Hardening::defaults() );
	}
	MVN_Signature_Pack::install_from_bundled();
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
	// Quarantine folder and scan history are intentionally preserved.
	MVN_Perf::disarm();
	MVN_Scheduler::deactivate();
}

MVN_Hardening::instance()->boot();
MVN_Http_Guard::instance()->boot();
MVN_Perf::instance()->boot();
MVN_Scheduler::boot();

// Refresh bundled signature pack when plugin version advances.
$mvn_installed_ver = get_option( 'mvn_plugin_version', '' );
if ( $mvn_installed_ver !== MVN_VERSION ) {
	mvn_install_capabilities();
	MVN_Signature_Pack::install_from_bundled();
	update_option( 'mvn_plugin_version', MVN_VERSION, false );
}

if ( is_admin() ) {
	require_once MVN_PLUGIN_DIR . 'admin/class-mvn-admin.php';
	MVN_Admin::instance()->boot();
}
