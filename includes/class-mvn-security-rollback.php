<?php
/**
 * Rollback for Security Architecture migration.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Security_Rollback {

	/**
	 * Restore pre-gateway public root from migration backup + switch bak.
	 *
	 * @param array                  $state  Migration option state.
	 * @param MVN_Security_Logger|null $logger Logger.
	 * @return true|WP_Error
	 */
	public static function run( array $state, $logger = null ) {
		$public = isset( $state['public_path'] ) ? mvn_normalize_path( $state['public_path'] ) : '';
		$backup = isset( $state['backup_dir'] ) ? mvn_normalize_path( $state['backup_dir'] ) : '';
		$core   = isset( $state['core_path'] ) ? mvn_normalize_path( $state['core_path'] ) : '';

		if ( ! $public || ! is_dir( $public ) ) {
			return new WP_Error( 'no_public', 'مسیر ریشه عمومی نامعتبر است.' );
		}
		if ( ! $backup || ! is_dir( $backup ) ) {
			return new WP_Error( 'no_backup', 'بک‌آپ مهاجرت پیدا نشد؛ بازگشت امن ممکن نیست.' );
		}

		if ( $logger ) {
			$logger->info( 'Rollback started' );
		}

		self::disable_maintenance( $public, $core );

		$switch_bak = $public . '/.mvn-pre-gateway-bak';
		$links      = MVN_Security_Migration::public_link_names();

		// Remove gateway symlinks / gateway files first.
		foreach ( $links as $name ) {
			$target = $public . '/' . $name;
			if ( is_link( $target ) || ( file_exists( $target ) && ! is_dir( $switch_bak . '/' . $name ) ) ) {
				// Only remove if we have a bak restore candidate or it is a symlink we created.
				if ( is_link( $target ) ) {
					@unlink( $target );
				}
			}
		}
		if ( is_file( $public . '/index.php' ) && false !== strpos( (string) @file_get_contents( $public . '/index.php' ), 'MVN_SECURITY_GATEWAY' ) ) {
			@unlink( $public . '/index.php' );
		}
		if ( is_file( $public . '/.htaccess' ) && false !== strpos( (string) @file_get_contents( $public . '/.htaccess' ), 'MVN Security Gateway' ) ) {
			@unlink( $public . '/.htaccess' );
		}

		// Restore switched-away trees from .mvn-pre-gateway-bak.
		if ( is_dir( $switch_bak ) ) {
			foreach ( $links as $name ) {
				$src = $switch_bak . '/' . $name;
				$dst = $public . '/' . $name;
				if ( ! file_exists( $src ) && ! is_link( $src ) ) {
					continue;
				}
				if ( is_link( $dst ) || file_exists( $dst ) ) {
					self::force_remove( $dst );
				}
				if ( ! @rename( $src, $dst ) ) {
					if ( ! self::copy_path( $src, $dst ) ) {
						return new WP_Error( 'restore_fail', 'بازگردانی ناموفق: ' . $name );
					}
					self::force_remove( $src );
				}
			}
			self::force_remove( $switch_bak );
		}

		// Restore index/.htaccess from migration backup snapshots.
		$bak_index = $backup . '/public-index.php';
		$bak_ht    = $backup . '/public-htaccess';
		if ( is_file( $bak_index ) ) {
			if ( ! @copy( $bak_index, $public . '/index.php' ) ) {
				return new WP_Error( 'restore_index', 'بازگردانی index.php ناموفق بود.' );
			}
		}
		if ( is_file( $bak_ht ) ) {
			@copy( $bak_ht, $public . '/.htaccess' );
		} elseif ( is_file( $public . '/.htaccess' ) && false !== strpos( (string) @file_get_contents( $public . '/.htaccess' ), 'MVN Security Gateway' ) ) {
			@unlink( $public . '/.htaccess' );
		}

		// Optionally remove incomplete core copy when rollback before completed cleanup.
		if ( $core && is_dir( $core ) && ! empty( $state['remove_core_on_rollback'] ) ) {
			self::force_remove( $core );
		}

		self::disable_maintenance( $public, $core );

		if ( $logger ) {
			$logger->info( 'Rollback finished' );
		}
		return true;
	}

	/**
	 * @param string      $public Public path.
	 * @param string|null $core   Core path.
	 */
	public static function disable_maintenance( $public, $core = null ) {
		foreach ( array_filter( array( $public, $core ) ) as $root ) {
			$file = trailingslashit( $root ) . '.maintenance';
			if ( is_file( $file ) ) {
				@unlink( $file );
			}
		}
	}

	/**
	 * @param string $path Path.
	 * @return bool
	 */
	public static function force_remove( $path ) {
		$path = (string) $path;
		if ( '' === $path || '/' === $path || ! file_exists( $path ) && ! is_link( $path ) ) {
			return true;
		}
		if ( is_link( $path ) || is_file( $path ) ) {
			return @unlink( $path );
		}
		if ( ! is_dir( $path ) ) {
			return false;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $it as $item ) {
				/** @var SplFileInfo $item */
				$p = $item->getPathname();
				if ( $item->isLink() || $item->isFile() ) {
					@unlink( $p );
				} else {
					@rmdir( $p );
				}
			}
		} catch ( Exception $e ) {
			return false;
		}
		return @rmdir( $path );
	}

	/**
	 * @param string $src Source.
	 * @param string $dst Dest.
	 * @return bool
	 */
	private static function copy_path( $src, $dst ) {
		if ( is_link( $src ) || is_file( $src ) ) {
			$dir = dirname( $dst );
			if ( ! is_dir( $dir ) ) {
				wp_mkdir_p( $dir );
			}
			return @copy( $src, $dst );
		}
		if ( ! is_dir( $src ) ) {
			return false;
		}
		if ( ! is_dir( $dst ) && ! wp_mkdir_p( $dst ) ) {
			return false;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $src, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			foreach ( $it as $item ) {
				/** @var SplFileInfo $item */
				$rel  = substr( $item->getPathname(), strlen( $src ) );
				$rel  = ltrim( str_replace( '\\', '/', $rel ), '/' );
				$to   = $dst . '/' . $rel;
				if ( $item->isDir() ) {
					if ( ! is_dir( $to ) && ! wp_mkdir_p( $to ) ) {
						return false;
					}
				} else {
					$dir = dirname( $to );
					if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
						return false;
					}
					if ( ! @copy( $item->getPathname(), $to ) ) {
						return false;
					}
				}
			}
		} catch ( Exception $e ) {
			return false;
		}
		return true;
	}
}
