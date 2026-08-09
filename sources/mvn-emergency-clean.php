<?php
/**
 * MVN Emergency Cleaner — standalone (no WordPress).
 *
 * WHY: The xdav-tracker / Zonal Runner Tap family reinfects via an auto_prepend
 * shell (.user.ini -> hex .php) that runs BEFORE WordPress on every request, so
 * cleanup from inside wp-admin keeps losing the race. This script runs on its own.
 *
 * HOW TO USE (host File Manager / FTP):
 *   1) Edit MVN_TOKEN below to a long secret (change it!).
 *   2) Upload this file to your site root next to wp-config.php
 *      (e.g. domains/khodebinahayat.com/public_html/mvn-emergency-clean.php).
 *   3) POST the endpoint with header: Authorization: Bearer YOUR_SECRET
 *   4) Refresh 3-4 times over ~30 seconds. It neutralizes the prepend chain,
 *      empties/locks .user.ini, and removes reinfectors in a loop.
 *   5) DELETE this file when done, then rotate all passwords / FTP / DB.
 *
 * NOTE: Full success on a Linux host usually also needs SSH:
 *   chattr -i <files>; rm -f <files>; and a PHP-FPM restart to flush the
 *   .user.ini cache. Ask your host to restart PHP after cleaning.
 */

define( 'MVN_TOKEN', 'CHANGE_ME_TO_A_LONG_SECRET' );
define( 'MVN_ALLOWED_IPS', '' ); // Optional comma-separated exact IPs.

if ( 'CHANGE_ME_TO_A_LONG_SECRET' === MVN_TOKEN ) {
	http_response_code( 503 );
	exit( 'Edit MVN_TOKEN before running this emergency cleaner.' );
}
if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '' ) ) {
	header( 'Allow: POST' );
	http_response_code( 405 );
	exit( 'POST required' );
}
$remote_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
$allowed_ips = array_filter( array_map( 'trim', explode( ',', MVN_ALLOWED_IPS ) ) );
if ( $allowed_ips && ! in_array( $remote_ip, $allowed_ips, true ) ) {
	http_response_code( 403 );
	exit( 'Forbidden' );
}
$rate_file = __DIR__ . '/.mvn-emergency-rate.json';
$rate      = is_file( $rate_file ) ? json_decode( (string) @file_get_contents( $rate_file ), true ) : array();
$ip_key    = hash( 'sha256', $remote_ip );
$attempts  = isset( $rate[ $ip_key ] ) && is_array( $rate[ $ip_key ] ) ? $rate[ $ip_key ] : array();
$attempts  = array_values( array_filter( $attempts, static function ( $ts ) { return (int) $ts > time() - 900; } ) );
if ( count( $attempts ) >= 5 ) {
	http_response_code( 429 );
	header( 'Retry-After: 900' );
	exit( 'Too many attempts' );
}
$auth = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? trim( (string) $_SERVER['HTTP_AUTHORIZATION'] ) : '';
$token = 0 === stripos( $auth, 'Bearer ' ) ? trim( substr( $auth, 7 ) ) : '';
if ( ! hash_equals( MVN_TOKEN, $token ) ) {
	$attempts[] = time();
	$rate[ $ip_key ] = $attempts;
	@file_put_contents( $rate_file, json_encode( $rate ), LOCK_EX );
	http_response_code( 403 );
	exit( 'Forbidden' );
}
unset( $rate[ $ip_key ] );
@file_put_contents( $rate_file, json_encode( $rate ), LOCK_EX );

if ( isset( $_POST['action'] ) && 'self_delete' === $_POST['action'] ) {
	if ( @unlink( __FILE__ ) ) {
		@unlink( $rate_file );
		exit( 'Emergency cleaner deleted.' );
	}
	http_response_code( 500 );
	exit( 'Self-delete failed; remove this file manually.' );
}

@set_time_limit( 60 );
header( 'Content-Type: text/plain; charset=utf-8' );

$docroot = __DIR__;
$content = is_dir( $docroot . '/wp-content' ) ? $docroot . '/wp-content' : $docroot;
$log     = array();

function mvn_ec_can_exec() {
	return function_exists( 'exec' ) || function_exists( 'shell_exec' );
}
function mvn_ec_chattr( $path, $flag ) {
	if ( ! mvn_ec_can_exec() || stripos( PHP_OS, 'WIN' ) === 0 ) {
		return;
	}
	$cmd = 'chattr ' . $flag . ' ' . escapeshellarg( $path ) . ' 2>/dev/null';
	if ( function_exists( 'exec' ) ) {
		@exec( $cmd );
	} else {
		@shell_exec( $cmd );
	}
}
function mvn_ec_rm( $path, &$log ) {
	if ( is_file( $path ) ) {
		mvn_ec_chattr( $path, '-i' );
		@chmod( $path, 0644 );
		$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, array( 'php', 'phtml', 'inc' ), true ) ) {
			@file_put_contents( $path, "<?php\n/* removed */\n" );
		}
		if ( ! @unlink( $path ) ) {
			@rename( $path, $path . '.__mvn_dead' );
			@unlink( $path . '.__mvn_dead' );
		}
		if ( ! is_file( $path ) ) {
			$log[] = 'deleted: ' . $path;
		} else {
			$log[] = 'LOCKED (need SSH): ' . $path;
		}
		return;
	}
	if ( is_dir( $path ) ) {
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $it as $f ) {
			$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
		}
		@rmdir( $path );
		$log[] = 'deleted dir: ' . $path;
	}
}
function mvn_ec_stub_lock( $path, &$log ) {
	mvn_ec_chattr( $path, '-i' );
	@chmod( $path, 0644 );
	if ( false !== @file_put_contents( $path, "<?php\n/* MVN Safe prepend stub. */\n" ) ) {
		mvn_ec_chattr( $path, '+i' );
		$log[] = 'stub+lock: ' . $path;
	}
}
function mvn_ec_is_safe( $path ) {
	if ( ! is_file( $path ) ) {
		return false;
	}
	$head = (string) @file_get_contents( $path, false, null, 0, 256 );
	return false !== strpos( $head, 'MVN Safe' ) || false !== strpos( $head, 'Neutralized by' );
}
function mvn_ec_parse_prepend( $file ) {
	$out = array();
	$c   = (string) @file_get_contents( $file );
	if ( preg_match_all( '/auto_(?:pre|ap)pend_file\s*[=\s]\s*["\']?([^"\'\r\n;]+)/i', $c, $m ) ) {
		foreach ( $m[1] as $raw ) {
			$raw = trim( $raw );
			if ( '' === $raw || 'none' === strtolower( $raw ) ) {
				continue;
			}
			if ( ! preg_match( '#^(?:/|[A-Za-z]:[\\\\/])#', $raw ) ) {
				$raw = rtrim( dirname( $file ), '/\\' ) . '/' . ltrim( $raw, '/\\' );
			}
			$out[] = $raw;
		}
	}
	return $out;
}

// 1) Neutralize auto_prepend chain in docroot + wp-content.
foreach ( array( $docroot, $content, dirname( $docroot ) ) as $d ) {
	foreach ( array( '.user.ini', 'user.ini', 'php.ini' ) as $name ) {
		$ini = $d . '/' . $name;
		if ( ! is_file( $ini ) ) {
			continue;
		}
		foreach ( mvn_ec_parse_prepend( $ini ) as $target ) {
			if ( is_file( $target ) ) {
				mvn_ec_stub_lock( $target, $log );
			} elseif ( is_dir( dirname( $target ) ) ) {
				mvn_ec_stub_lock( $target, $log );
			}
		}
		mvn_ec_chattr( $ini, '-i' );
		if ( false !== @file_put_contents( $ini, "; Neutralized by MVN Safe emergency cleaner\n" ) ) {
			mvn_ec_chattr( $ini, '+i' );
			$log[] = 'emptied+lock: ' . $ini;
		}
	}
	$ht = $d . '/.htaccess';
	if ( is_file( $ht ) ) {
		$c  = (string) @file_get_contents( $ht );
		$c2 = preg_replace( '/^\s*php_(?:value|flag)\s+auto_(?:pre|ap)pend_file.*$/im', '', $c );
		if ( null !== $c2 && $c2 !== $c ) {
			mvn_ec_chattr( $ht, '-i' );
			@file_put_contents( $ht, $c2 );
			$log[] = 'htaccess prepend removed: ' . $ht;
		}
	}
}

// 2) Remove wp-content root shells / hex / zip / bad drop-ins.
foreach ( scandir( $content ) ?: array() as $e ) {
	if ( '.' === $e || '..' === $e ) {
		continue;
	}
	$p = $content . '/' . $e;
	if ( is_file( $p ) && (
		preg_match( '/^\.?[a-f0-9]{6,16}\.(?:php|zip)$/i', $e )
		|| in_array( $e, array( '.user.ini', 'user.ini' ), true )
	) ) {
		if ( mvn_ec_is_safe( $p ) ) {
			continue;
		}
		mvn_ec_rm( $p, $log );
	}
}
foreach ( array( 'db.php', 'advanced-cache.php', 'object-cache.php' ) as $drop ) {
	$p = $content . '/' . $drop;
	if ( ! is_file( $p ) ) {
		continue;
	}
	$raw = (string) @file_get_contents( $p );
	if ( false !== strpos( $raw, 'MVN Safe' ) ) {
		continue;
	}
	if ( preg_match( '/eval|base64_decode|gzinflate|zonal|xdav|auto_prepend/i', $raw ) ) {
		mvn_ec_rm( $p, $log );
	}
}

// 3) Wipe malware mu-plugins.
$mu = $content . '/mu-plugins';
if ( is_dir( $mu ) ) {
	foreach ( scandir( $mu ) ?: array() as $e ) {
		if ( '.' === $e || '..' === $e || 'index.php' === $e ) {
			continue;
		}
		if ( preg_match( '/zonal|xdav|security-helper|wp-[a-z0-9]{6}-loader/i', $e ) ) {
			mvn_ec_rm( $mu . '/' . $e, $log );
		}
	}
}

// 4) Remove known fake-plugin folders.
$plugins = $content . '/plugins';
if ( is_dir( $plugins ) ) {
	foreach ( scandir( $plugins ) ?: array() as $e ) {
		if ( '.' === $e || '..' === $e ) {
			continue;
		}
		if ( preg_match( '/zonal|xdav[-_]?tracker|security-helper|wp-compat/i', $e ) ) {
			mvn_ec_rm( $plugins . '/' . $e, $log );
		}
	}
}

echo "MVN Emergency Cleaner\n";
echo "docroot: $docroot\n";
echo "wp-content: $content\n\n";
echo empty( $log ) ? "No IoCs matched this pass (refresh again).\n" : implode( "\n", $log ) . "\n";
echo "\nPOST a few times. Then POST action=self_delete (same Authorization header), or delete this file manually.\n";
echo "If any line says LOCKED, use SSH: chattr -i <file> && rm -f <file>, then restart PHP-FPM.\n";
