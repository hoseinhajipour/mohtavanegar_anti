<?php
/**
 * Standalone Security Engine 2.0 tests.
 * Run: php tests/security-engine-tests.php
 */

$root = dirname( __DIR__ );
$tmp  = str_replace( '\\', '/', sys_get_temp_dir() . '/mvn-security-tests-' . getmypid() );
@mkdir( $tmp . '/site', 0777, true );
@mkdir( $tmp . '/content', 0777, true );

define( 'ABSPATH', $tmp . '/site/' );
define( 'WP_CONTENT_DIR', $tmp . '/content' );
define( 'MVN_PLUGIN_DIR', str_replace( '\\', '/', $root ) . '/' );
define( 'MVN_VERSION', '2.0.0' );
define( 'MVN_OPTION_ISSUES', 'mvn_scan_issues' );
define( 'DAY_IN_SECONDS', 86400 );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'MB_IN_BYTES', 1048576 );

$GLOBALS['mvn_test_options'] = array();
function apply_filters( $tag, $value ) { return $value; }
function wp_mkdir_p( $dir ) { return is_dir( $dir ) || mkdir( $dir, 0777, true ); }
function wp_json_encode( $value, $flags = 0 ) { return json_encode( $value, $flags ); }
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $value ) ); }
function wp_generate_password( $length = 12 ) { return substr( str_repeat( 'abcdef0123456789', 4 ), 0, $length ); }
function get_option( $key, $default = false ) { return array_key_exists( $key, $GLOBALS['mvn_test_options'] ) ? $GLOBALS['mvn_test_options'][ $key ] : $default; }
function add_option( $key, $value ) { if ( array_key_exists( $key, $GLOBALS['mvn_test_options'] ) ) return false; $GLOBALS['mvn_test_options'][ $key ] = $value; return true; }
function update_option( $key, $value ) { $GLOBALS['mvn_test_options'][ $key ] = $value; return true; }
function delete_option( $key ) { unset( $GLOBALS['mvn_test_options'][ $key ] ); return true; }
function wp_cache_delete() {}
function wp_cache_flush_runtime() {}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function mvn_signatures() { return array(); }
function mvn_clean_rules() { return array(); }
class WP_Error {
	private $code;
	private $message;
	public function __construct( $code, $message ) { $this->code = $code; $this->message = $message; }
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
}

require $root . '/includes/helpers.php';
require $root . '/includes/confidence.php';
require $root . '/includes/class-mvn-file-index.php';
require $root . '/includes/class-mvn-signature-pack.php';
require $root . '/includes/class-mvn-behavior-scanner.php';
require $root . '/includes/class-mvn-archive-scanner.php';
require $root . '/includes/class-mvn-quarantine.php';
require $root . '/includes/class-mvn-cleaner.php';

$tests = 0;
function mvn_assert( $condition, $message ) {
	global $tests;
	$tests++;
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
}

mvn_assert( mvn_abs_path( 'wp-content/a.php' ) === WP_CONTENT_DIR . '/a.php', 'custom WP_CONTENT_DIR' );
mvn_assert( false === mvn_abs_path( '../escape.php' ), 'traversal rejected' );
$atomic = ABSPATH . 'atomic.php';
mvn_assert( mvn_atomic_write( $atomic, "<?php echo 1;\n" ), 'atomic write' );
mvn_assert( false === mvn_atomic_write( dirname( ABSPATH ) . '/escape.php', 'x' ), 'outside write rejected' );

$issue = array( 'sig' => 'known_malware_hash', 'severity' => 'critical', 'confidence' => 99, 'rel' => 'wp-content/uploads/x.php', 'action' => 'quarantine_delete' );
mvn_assert( MVN_Cleaner::is_safe_auto_fix( $issue ), '95+ confirmed gate' );
$issue['confidence'] = 80;
mvn_assert( ! MVN_Cleaner::is_safe_auto_fix( $issue ) && 'caution' === MVN_Cleaner::risk_tier( $issue ), '65-94 confirmation gate' );
$issue['confidence'] = 50;
mvn_assert( 'manual' === MVN_Cleaner::risk_tier( $issue ), 'below 65 report gate' );

mvn_assert( MVN_Signature_Pack::regex_is_safe( '/eval\s*\(/i' ), 'safe regex accepted' );
mvn_assert( ! MVN_Signature_Pack::regex_is_safe( '/(a+)+$/' ), 'nested quantifier rejected' );
mvn_assert( ! is_wp_error( MVN_Signature_Pack::install_from_bundled() ), 'bundled schema-2 signature pack accepted' );
if ( function_exists( 'sodium_crypto_sign_keypair' ) && ! defined( 'MVN_SIGNATURE_PACK_PUBLIC_KEY' ) ) {
	$keypair = sodium_crypto_sign_keypair();
	define( 'MVN_SIGNATURE_PACK_PUBLIC_KEY', base64_encode( sodium_crypto_sign_publickey( $keypair ) ) );
	$message = '{"version":"2.0.1"}';
	$signature = base64_encode( sodium_crypto_sign_detached( $message, sodium_crypto_sign_secretkey( $keypair ) ) );
	$verify = new ReflectionMethod( 'MVN_Signature_Pack', 'verify_ed25519' );
	$verify->setAccessible( true );
	mvn_assert( true === $verify->invoke( null, $message, $signature ), 'valid Ed25519 accepted' );
	mvn_assert( is_wp_error( $verify->invoke( null, $message . 'tampered', $signature ) ), 'tampered Ed25519 rejected' );
}
$restore_check = new ReflectionMethod( 'MVN_Quarantine', 'payload_restore_safe' );
$restore_check->setAccessible( true );
mvn_assert( is_wp_error( $restore_check->invoke( null, '<?php echo 1;', 'wp-content/uploads/shell.php' ) ), 'malware-risk restore blocked by default' );
$behavior = MVN_Behavior_Scanner::analyze( 'drop.php', "<?php eval(base64_decode(\$_POST['x'])); file_put_contents('db.php',\$_POST['x']); \$f='system';\$f(\$_REQUEST['c']);/*auto_prepend_file*/" );
mvn_assert( is_array( $behavior ) && $behavior['confidence'] >= 95, 'behavior engine' );

$mtime = filemtime( $atomic );
$size  = filesize( $atomic );
MVN_File_Index::mark( 'atomic.php', true, $mtime, $size, hash_file( 'sha256', $atomic ) );
MVN_File_Index::flush();
mvn_assert( MVN_File_Index::is_unchanged_clean( 'atomic.php', $mtime, $size, hash_file( 'sha256', $atomic ) ), 'SHA incremental match' );
mvn_atomic_write( $atomic, "<?php echo 2;\n" );
mvn_assert( ! MVN_File_Index::is_unchanged_clean( 'atomic.php', $mtime, $size, hash_file( 'sha256', $atomic ) ), 'metadata bypass blocked' );

if ( class_exists( 'ZipArchive' ) ) {
	$path = WP_CONTENT_DIR . '/fixture.zip';
	$zip  = new ZipArchive();
	$zip->open( $path, ZipArchive::CREATE | ZipArchive::OVERWRITE );
	$zip->addFromString( '../escape.php', 'fixture' );
	$zip->addFromString( 'ratio.txt', str_repeat( 'A', 2 * MB_IN_BYTES ) );
	$zip->close();
	$sigs = array_column( MVN_Archive_Scanner::scan( $path, 'wp-content/uploads/fixture.zip' ), 'sig' );
	mvn_assert( in_array( 'archive_zip_slip', $sigs, true ), 'zip-slip guard' );
	mvn_assert( in_array( 'archive_bomb', $sigs, true ), 'archive bomb guard' );
}

$db_source = file_get_contents( $root . '/includes/class-mvn-db-scanner.php' );
mvn_assert( false === strpos( $db_source, 'LIMIT %d OFFSET %d' ), 'keyset pagination' );
mvn_assert( false !== strpos( $db_source, 'commentmeta' ) && false !== strpos( $db_source, 'sitemeta' ), 'extended DB coverage' );
$ghost_source = file_get_contents( $root . '/includes/class-mvn-ghost-plugins.php' );
mvn_assert( false !== strpos( $ghost_source, 'confirmed_mu_plugin_ioc' ) && false === strpos( $ghost_source, "'mu_plugin_wipe'" ), 'benign MU blanket deletion removed' );
$plugin_repair = file_get_contents( $root . '/includes/class-mvn-plugin-repair.php' );
$theme_repair  = file_get_contents( $root . '/includes/class-mvn-theme-repair.php' );
mvn_assert( false !== strpos( $plugin_repair, '.mvn-stage-' ) && false !== strpos( $plugin_repair, 'function rollback' ), 'plugin staging and rollback present' );
mvn_assert( false !== strpos( $theme_repair, '.mvn-stage-' ) && false !== strpos( $theme_repair, 'function rollback' ), 'theme staging and rollback present' );
$manifest = json_decode( file_get_contents( $root . '/sources/integrity-manifest.json' ), true );
$manifest_ok = ! empty( $manifest['files'] );
foreach ( isset( $manifest['files'] ) ? $manifest['files'] : array() as $rel => $hash ) {
	$manifest_ok = $manifest_ok && is_file( $root . '/' . $rel ) && hash_equals( $hash, hash_file( 'sha256', $root . '/' . $rel ) );
}
mvn_assert( $manifest_ok, 'bundled self-integrity manifest' );

echo "OK: {$tests} security engine tests passed.\n";
