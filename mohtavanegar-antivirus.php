<?php
/**
 * Plugin Name:       Mohtavanegar Antivirus
 * Plugin URI:        https://mohtavanegar.local/
 * Description:       آنتی‌ویروس وردپرس: اسکن بدافزار، حذف کدهای تزریق‌شده، تعمیر فایل‌های هسته از سورس سالم، بازیابی htaccess، حذف htaccess های جعلی، سخت‌سازی امنیتی (Brute Force، XMLRPC، سطح دسترسی‌ها).
 * Version:           1.4.0
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Mohtavanegar Security
 * License:           GPLv2 or later
 * Text Domain:       mvn
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MVN_VERSION', '1.4.0' );
define( 'MVN_PLUGIN_FILE', __FILE__ );
define( 'MVN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'MVN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'MVN_SOURCE_ZIP', MVN_PLUGIN_DIR . 'sources/wordpress_core.zip' );
define( 'MVN_SOURCE_HTACCESS', MVN_PLUGIN_DIR . 'sources/default.htaccess' );
define( 'MVN_OPTION_ISSUES', 'mvn_scan_issues' );
define( 'MVN_OPTION_HARDENING', 'mvn_hardening' );
define( 'MVN_OPTION_LASTSCAN', 'mvn_last_scan' );
define( 'MVN_NONCE_ACTION', 'mvn_ajax_nonce' );

require_once MVN_PLUGIN_DIR . 'includes/helpers.php';
require_once MVN_PLUGIN_DIR . 'includes/signatures.php';
require_once MVN_PLUGIN_DIR . 'includes/confidence.php';
require_once MVN_PLUGIN_DIR . 'includes/signatures-db.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-file-index.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-ignore-list.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-db-scanner.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-core-integrity.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-quarantine.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-scanner.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-cleaner.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-htaccess-guard.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-core-repair.php';
require_once MVN_PLUGIN_DIR . 'includes/repo-plugins.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-plugin-repair.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-permissions.php';
require_once MVN_PLUGIN_DIR . 'includes/class-mvn-hardening.php';

register_activation_hook( __FILE__, 'mvn_activate' );
register_deactivation_hook( __FILE__, 'mvn_deactivate' );

function mvn_activate() {
	mvn_ensure_data_dirs();
	if ( false === get_option( MVN_OPTION_HARDENING ) ) {
		add_option( MVN_OPTION_HARDENING, MVN_Hardening::defaults() );
	}
}

function mvn_deactivate() {
	// Quarantine folder and scan history are intentionally preserved.
}

MVN_Hardening::instance()->boot();

if ( is_admin() ) {
	require_once MVN_PLUGIN_DIR . 'admin/class-mvn-admin.php';
	MVN_Admin::instance()->boot();
}
