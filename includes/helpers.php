<?php
/**
 * Shared helpers: data directory, JSON state, paths, IP, logging.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base data directory (outside plugin, survives plugin updates).
 */
function mvn_data_dir() {
	$dir = WP_CONTENT_DIR . '/mvn-data';
	return apply_filters( 'mvn_data_dir', $dir );
}

function mvn_ensure_data_dirs() {
	$base  = mvn_data_dir();
	$dirs  = array( $base, $base . '/quarantine', $base . '/backups', $base . '/backups/plugins', $base . '/logs', $base . '/state' );
	$ht    = "# BEGIN Mohtavanegar\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n# END Mohtavanegar\n";
	foreach ( $dirs as $dir ) {
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		if ( is_dir( $dir ) && ! file_exists( $dir . '/index.php' ) ) {
			@file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" );
		}
	}
	if ( is_dir( $base ) && ! file_exists( $base . '/.htaccess' ) ) {
		@file_put_contents( $base . '/.htaccess', $ht );
	}
	return $base;
}

/**
 * Read a JSON state file.
 */
function mvn_state_read( $name, $default = array() ) {
	$file = mvn_data_dir() . '/state/' . preg_replace( '/[^a-z0-9_\-]/i', '', $name ) . '.json';
	if ( ! file_exists( $file ) ) {
		return $default;
	}
	$raw  = @file_get_contents( $file );
	$data = json_decode( $raw, true );
	return is_array( $data ) ? $data : $default;
}

/**
 * Write a JSON state file.
 */
function mvn_state_write( $name, $data ) {
	mvn_ensure_data_dirs();
	$file = mvn_data_dir() . '/state/' . preg_replace( '/[^a-z0-9_\-]/i', '', $name ) . '.json';
	return (bool) @file_put_contents( $file, wp_json_encode( $data ) );
}

function mvn_state_delete( $name ) {
	$file = mvn_data_dir() . '/state/' . preg_replace( '/[^a-z0-9_\-]/i', '', $name ) . '.json';
	if ( file_exists( $file ) ) {
		@unlink( $file );
	}
}

/**
 * Absolute path from a site-relative path, guarded against traversal.
 */
function mvn_abs_path( $rel ) {
	$rel  = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
	$base = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
	$path = $base . '/' . $rel;
	// Block directory traversal.
	if ( false !== strpos( $rel, '..' ) ) {
		return false;
	}
	return $path;
}

/**
 * Site-relative path from an absolute path.
 */
function mvn_rel_path( $abs ) {
	$abs  = str_replace( '\\', '/', $abs );
	$base = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/';
	if ( 0 === strpos( $abs, $base ) ) {
		return substr( $abs, strlen( $base ) );
	}
	return $abs;
}

/**
 * Real client IP (REMOTE_ADDR only - headers are spoofable).
 */
function mvn_get_ip() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
	return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
}

/**
 * Append a line to the plugin log.
 */
function mvn_log( $message ) {
	$dir = mvn_data_dir() . '/logs';
	if ( ! is_dir( $dir ) ) {
		mvn_ensure_data_dirs();
	}
	$line = '[' . gmdate( 'Y-m-d H:i:s' ) . '] ' . $message . "\n";
	@file_put_contents( $dir . '/activity.log', $line, FILE_APPEND | LOCK_EX );
}

/**
 * Folder names of this antivirus plugin (never scan/fix our own files).
 */
function mvn_self_plugin_slugs() {
	$slugs = array(
		'mohtavanegar-antivirus',
		'mohtavanegar_anti',
		'mohtavanegar-anti',
	);
	if ( defined( 'MVN_PLUGIN_FILE' ) ) {
		$slugs[] = basename( dirname( MVN_PLUGIN_FILE ) );
	}
	return array_unique( apply_filters( 'mvn_self_plugin_slugs', $slugs ) );
}

function mvn_is_self_plugin_path( $rel ) {
	$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
	foreach ( mvn_self_plugin_slugs() as $slug ) {
		$base = 'wp-content/plugins/' . $slug;
		if ( $rel === $base || 0 === strpos( $rel, $base . '/' ) ) {
			return true;
		}
	}
	return false;
}

/**
 * WordPress core file paths (repaired from bundled zip — not signature-scanned).
 */
function mvn_core_root_files() {
	return array(
		'index.php',
		'wp-load.php',
		'wp-settings.php',
		'wp-blog-header.php',
		'wp-cron.php',
		'wp-login.php',
		'wp-signup.php',
		'wp-trackback.php',
		'wp-comments-post.php',
		'wp-mail.php',
		'wp-activate.php',
		'xmlrpc.php',
		'wp-links-opml.php',
	);
}

function mvn_is_core_path( $rel ) {
	$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
	if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
		return true;
	}
	return in_array( $rel, mvn_core_root_files(), true );
}

/**
 * Should this file be excluded from malware signature scanning?
 */
function mvn_is_skippable_scan_file( $rel ) {
	$rel = trim( str_replace( '\\', '/', (string) $rel ), '/' );
	if ( mvn_is_core_path( $rel ) ) {
		return true;
	}
	if ( mvn_is_self_plugin_path( $rel ) ) {
		return true;
	}
	if ( mvn_is_skippable_dir( dirname( $rel ) ) ) {
		return true;
	}
	// Composer / npm dependencies — high false-positive rate; repair plugins from repo instead.
	if ( preg_match( '#/(vendor|node_modules)/#', $rel ) ) {
		return true;
	}
	// Wordfence runtime data (rules cache, config blobs).
	if ( 0 === strpos( $rel, 'wp-content/wflogs/' ) ) {
		return true;
	}
	return (bool) apply_filters( 'mvn_skip_scan_file', false, $rel );
}

/**
 * Is this path inside a directory the scanner should skip?
 */
function mvn_is_skippable_dir( $rel ) {
	$rel = trim( str_replace( '\\', '/', $rel ), '/' );
	$skip = array(
		'wp-content/mvn-data',
		'wp-content/cache',
		'wp-content/upgrade',
		'wp-content/uploads/cache',
		'wp-content/wflogs',
	);
	foreach ( mvn_self_plugin_slugs() as $slug ) {
		$skip[] = 'wp-content/plugins/' . $slug;
	}
	foreach ( $skip as $s ) {
		if ( $rel === $s || 0 === strpos( $rel, $s . '/' ) ) {
			return true;
		}
		if ( false !== strpos( $rel, '/.git' ) || false !== strpos( $rel, '/node_modules' ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Extensions the scanner treats as code / injectable content.
 */
function mvn_scannable_extensions() {
	return array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'pht', 'inc', 'module', 'js', 'html', 'htm', 'svg', 'txt', 'htaccess' );
}

/**
 * Binary/archive extensions never scanned.
 */
function mvn_binary_extensions() {
	return array( 'zip', 'gz', 'tar', 'rar', '7z', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'mp4', 'mp3', 'avi', 'mov', 'pdf', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'exe', 'dll', 'so', 'psd', 'ai', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'sql' );
}

/**
 * Human readable file size.
 */
function mvn_size_format( $bytes ) {
	$bytes = (float) $bytes;
	if ( $bytes >= 1048576 ) {
		return round( $bytes / 1048576, 1 ) . ' MB';
	}
	if ( $bytes >= 1024 ) {
		return round( $bytes / 1024, 1 ) . ' KB';
	}
	return $bytes . ' B';
}

/**
 * List files under a directory; paths are relative to $root_abs (not ABSPATH).
 *
 * @param string $root_abs Absolute directory.
 * @param int    $max      Max files.
 * @return string[]
 */
function mvn_list_files_in( $root_abs, $max = 200000 ) {
	$out      = array();
	$root_abs = rtrim( str_replace( '\\', '/', $root_abs ), '/' );
	if ( ! is_dir( $root_abs ) ) {
		return $out;
	}
	$stack = array( $root_abs );
	while ( ! empty( $stack ) && count( $out ) < $max ) {
		$dir   = array_pop( $stack );
		$items = @scandir( $dir );
		if ( false === $items ) {
			continue;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_link( $path ) ) {
				continue;
			}
			if ( is_dir( $path ) ) {
				$stack[] = $path;
			} else {
				$out[] = ltrim( substr( str_replace( '\\', '/', $path ), strlen( $root_abs ) ), '/' );
				if ( count( $out ) >= $max ) {
					break;
				}
			}
		}
	}
	sort( $out );
	return $out;
}

/**
 * Recursive directory listing (files only), site-relative, with skip rules.
 *
 * @param string $root_abs Absolute start directory.
 * @param int    $max      Safety cap on number of files.
 * @return string[] Relative file paths.
 */
function mvn_list_files( $root_abs, $max = 200000 ) {
	$out      = array();
	$root_abs = rtrim( str_replace( '\\', '/', $root_abs ), '/' );
	if ( ! is_dir( $root_abs ) ) {
		return $out;
	}
	$stack = array( $root_abs );
	while ( ! empty( $stack ) && count( $out ) < $max ) {
		$dir = array_pop( $stack );
		$items = @scandir( $dir );
		if ( false === $items ) {
			continue;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_link( $path ) ) {
				continue;
			}
			if ( is_dir( $path ) ) {
				if ( ! mvn_is_skippable_dir( mvn_rel_path( $path ) ) ) {
					$stack[] = $path;
				}
			} else {
				$out[] = mvn_rel_path( $path );
				if ( count( $out ) >= $max ) {
					break;
				}
			}
		}
	}
	sort( $out );
	return $out;
}
