<?php
/**
 * Block reinfection staging paths under wp-content.
 *
 * Malware often recreates wp-content/cache, wp-content/wpo-cache, and wp-content/db.php.
 * We delete them and place non-directory blockers so mkdir() with those names fails.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Path_Blocker {

	const OPTION_ENABLED = 'mvn_path_blocker_enabled';

	/**
	 * Relative names under WP_CONTENT_DIR that must never exist as directories.
	 *
	 * @return string[]
	 */
	public static function blocked_dirs() {
		return apply_filters(
			'mvn_blocked_content_dirs',
			array( 'cache', 'wpo-cache' )
		);
	}

	/**
	 * Relative drop-in files that must never exist (including former MVN safe stubs).
	 *
	 * @return string[]
	 */
	public static function blocked_files() {
		return apply_filters(
			'mvn_blocked_content_files',
			array( 'db.php' )
		);
	}

	public static function is_enabled() {
		// Default ON — these paths are known reinfection vectors on compromised sites.
		$raw = get_option( self::OPTION_ENABLED, null );
		if ( null === $raw ) {
			return (bool) apply_filters( 'mvn_path_blocker_enabled', true );
		}
		return (bool) apply_filters( 'mvn_path_blocker_enabled', (bool) $raw );
	}

	public static function set_enabled( $on ) {
		update_option( self::OPTION_ENABLED, $on ? 1 : 0, false );
		if ( $on ) {
			self::enforce();
		}
		return (bool) $on;
	}

	public static function boot() {
		if ( ! self::is_enabled() ) {
			return;
		}
		// As early as possible after plugins load; also shutdown in case malware rewrites later.
		add_action( 'plugins_loaded', array( __CLASS__, 'enforce' ), 0 );
		add_action( 'shutdown', array( __CLASS__, 'enforce' ), 0 );
	}

	/**
	 * Remove blocked paths and place directory blockers.
	 *
	 * @return array{removed:string[],blocked:string[],errors:string[]}
	 */
	public static function enforce() {
		static $running = false;
		if ( $running || ! self::is_enabled() || ! defined( 'WP_CONTENT_DIR' ) ) {
			return array(
				'removed' => array(),
				'blocked' => array(),
				'errors'  => array(),
			);
		}
		$running = true;
		$out     = array(
			'removed' => array(),
			'blocked' => array(),
			'errors'  => array(),
		);
		$base = WP_CONTENT_DIR;

		foreach ( self::blocked_files() as $name ) {
			$path = $base . '/' . $name;
			if ( ! file_exists( $path ) ) {
				continue;
			}
			if ( self::force_remove( $path ) ) {
				$out['removed'][] = 'wp-content/' . $name;
			} else {
				$out['errors'][] = 'حذف ناموفق: wp-content/' . $name;
			}
		}

		foreach ( self::blocked_dirs() as $name ) {
			$path = $base . '/' . $name;
			if ( is_dir( $path ) ) {
				if ( self::force_remove_tree( $path ) ) {
					$out['removed'][] = 'wp-content/' . $name . '/';
				} else {
					$out['errors'][] = 'حذف پوشه ناموفق: wp-content/' . $name;
				}
			}
			// File (not directory) with same name prevents mkdir() recreation.
			if ( is_dir( $path ) ) {
				$out['errors'][] = 'بلاکر قابل نصب نیست (پوشه هنوز هست): wp-content/' . $name;
				continue;
			}
			if ( is_file( $path ) && self::is_blocker_file( $path ) ) {
				$out['blocked'][] = 'wp-content/' . $name;
				continue;
			}
			if ( is_file( $path ) && ! self::is_blocker_file( $path ) ) {
				self::force_remove( $path );
			}
			$marker = "# MVN Path Block — do not delete.\n# Prevents malware from creating a {$name}/ staging directory.\n";
			if ( false !== @file_put_contents( $path, $marker ) ) {
				@chmod( $path, 0444 );
				$out['blocked'][] = 'wp-content/' . $name;
			} else {
				$out['errors'][] = 'نوشتن بلاکر ناموفق: wp-content/' . $name;
			}
		}

		$running = false;

		if ( $out['removed'] && class_exists( 'MVN_Security_Log', false ) ) {
			MVN_Security_Log::write( 'path_block', implode( ', ', $out['removed'] ), 'removed' );
		}

		return $out;
	}

	/**
	 * @param string $path Absolute path.
	 */
	public static function is_blocker_file( $path ) {
		if ( ! is_file( $path ) ) {
			return false;
		}
		$head = (string) @file_get_contents( $path, false, null, 0, 120 );
		return false !== strpos( $head, 'MVN Path Block' );
	}

	/**
	 * @param string $path Absolute file path.
	 */
	private static function force_remove( $path ) {
		if ( ! file_exists( $path ) ) {
			return true;
		}
		self::clear_attrs( $path );
		@chmod( $path, 0644 );
		if ( @unlink( $path ) ) {
			return true;
		}
		return @rename( $path, $path . '.__mvn_dead' );
	}

	/**
	 * @param string $dir Absolute directory.
	 */
	private static function force_remove_tree( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return true;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $it as $file ) {
				$p = $file->getPathname();
				self::clear_attrs( $p );
				if ( $file->isDir() ) {
					@rmdir( $p );
				} else {
					@chmod( $p, 0644 );
					@unlink( $p );
				}
			}
		} catch ( Exception $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
			// continue to rmdir attempt
		}
		self::clear_attrs( $dir );
		return @rmdir( $dir ) || ! is_dir( $dir );
	}

	/**
	 * @param string $path Absolute path.
	 */
	private static function clear_attrs( $path ) {
		if ( function_exists( 'exec' ) && function_exists( 'escapeshellarg' ) && is_string( $path ) && $path ) {
			@exec( 'chattr -i ' . escapeshellarg( $path ) . ' 2>/dev/null' );
		}
	}
}
