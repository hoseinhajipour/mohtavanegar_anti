<?php
/**
 * .htaccess guard — restore root htaccess from bundled default, purge rogue ones.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Htaccess_Guard {

	/**
	 * Restore ABSPATH/.htaccess from the plugin's sources/default.htaccess.
	 * Backs up the current one first.
	 *
	 * @return true|WP_Error
	 */
	public static function restore_root() {
		$src = MVN_SOURCE_HTACCESS;
		if ( ! is_file( $src ) ) {
			return new WP_Error( 'no_source', 'فایل default.htaccess در پوشه sources پلاگین پیدا نشد.' );
		}
		$content = @file_get_contents( $src );
		if ( false === $content || '' === trim( $content ) ) {
			return new WP_Error( 'empty_source', 'منبع htaccess خالی است.' );
		}

		$dest = rtrim( ABSPATH, '/\\' ) . DIRECTORY_SEPARATOR . '.htaccess';

		if ( is_file( $dest ) ) {
			$rel = mvn_rel_path( $dest );
			MVN_Quarantine::store( $rel, array( 'reason' => 'htaccess-restore-backup' ) );
		}

		$ok = @file_put_contents( $dest, $content );
		if ( false === $ok ) {
			return new WP_Error( 'write_fail', 'نوشتن .htaccess ریشه ناموفق بود. سطح دسترسی را بررسی کنید.' );
		}
		@chmod( $dest, 0644 );
		mvn_log( 'Root .htaccess restored from plugin default.' );
		return true;
	}

	/**
	 * Compare current root htaccess with the default.
	 */
	public static function root_status() {
		$src  = MVN_SOURCE_HTACCESS;
		$dest = rtrim( ABSPATH, '/\\' ) . DIRECTORY_SEPARATOR . '.htaccess';
		$out  = array(
			'exists'       => is_file( $dest ),
			'source_ok'    => is_file( $src ),
			'matches'      => false,
			'current_hash' => null,
			'source_hash'  => null,
			'current_size' => null,
		);
		if ( $out['source_ok'] ) {
			$out['source_hash'] = md5_file( $src );
		}
		if ( $out['exists'] ) {
			$out['current_hash'] = md5_file( $dest );
			$out['current_size'] = filesize( $dest );
			$out['matches']      = ( $out['current_hash'] && $out['source_hash'] && $out['current_hash'] === $out['source_hash'] );
		}
		return $out;
	}

	/**
	 * Delete every non-root .htaccess that is flagged as rogue (or all non-root if $aggressive).
	 *
	 * @param bool $aggressive If true, delete ALL non-root htaccess (except mvn-data and safe uploads deny).
	 * @return array {deleted:int, skipped:int, errors:[]}
	 */
	public static function purge_rogue( $aggressive = false ) {
		$list    = MVN_Scanner::find_all_htaccess();
		$deleted = 0;
		$skipped = 0;
		$errors  = array();
		$root    = '.htaccess';

		foreach ( $list as $rel ) {
			if ( $rel === $root ) {
				$skipped++;
				continue;
			}
			// Never touch our own data dir.
			if ( 0 === strpos( $rel, 'wp-content/mvn-data/' ) ) {
				$skipped++;
				continue;
			}

			$abs = mvn_abs_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				$skipped++;
				continue;
			}
			$content = (string) @file_get_contents( $abs );

			$is_rogue = false;
			if ( preg_match( '/php_value|php_flag|auto_prepend_file|auto_append_file|SetHandler|AddHandler/i', $content ) ) {
				$is_rogue = true;
			} elseif ( preg_match( '/RewriteEngine\s+On/i', $content ) && preg_match( '/RewriteRule/i', $content ) ) {
				$is_rogue = true;
			} elseif ( $aggressive ) {
				// Keep pure "deny PHP" uploads htaccess.
				$is_safe_uploads = (
					0 === strpos( $rel, 'wp-content/uploads/' )
					&& preg_match( '/<(?:Files|FilesMatch)/i', $content )
					&& preg_match( '/Require all denied|Deny from all/i', $content )
					&& ! preg_match( '/RewriteRule|php_value|auto_prepend|SetHandler/i', $content )
				);
				$is_rogue = ! $is_safe_uploads;
			}

			if ( ! $is_rogue ) {
				$skipped++;
				continue;
			}

			$id = MVN_Quarantine::store( $rel, array( 'reason' => 'rogue_htaccess_purge' ) );
			if ( ! $id ) {
				$errors[] = $rel . ': قرنطینه ناموفق';
				continue;
			}
			if ( ! @unlink( $abs ) ) {
				$errors[] = $rel . ': حذف ناموفق';
				continue;
			}
			$deleted++;
			mvn_log( "Purged rogue htaccess: {$rel}" );
		}

		return compact( 'deleted', 'skipped', 'errors' );
	}
}
