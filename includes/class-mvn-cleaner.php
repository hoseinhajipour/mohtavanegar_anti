<?php
/**
 * Cleaner / Fix engine — strip injected malware, quarantine, delete.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Cleaner {

	/**
	 * Fix a single issue by its id (from last scan).
	 *
	 * @return true|WP_Error
	 */
	public static function fix_issue( $issue_id ) {
		$issues = MVN_Scanner::get_issues();
		$target = null;
		$idx    = null;
		foreach ( $issues as $i => $issue ) {
			if ( isset( $issue['id'] ) && $issue['id'] === $issue_id ) {
				$target = $issue;
				$idx    = $i;
				break;
			}
		}
		if ( ! $target ) {
			return new WP_Error( 'not_found', 'مشکل پیدا نشد (ممکن است قبلاً رفع شده باشد).' );
		}

		$result = self::apply( $target );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Remove from stored issues.
		array_splice( $issues, $idx, 1 );
		update_option( MVN_OPTION_ISSUES, $issues, false );

		// Also update in-progress scan state if present.
		$state = MVN_Scanner::get_state();
		if ( ! empty( $state['issues'] ) ) {
			$state['issues'] = array_values(
				array_filter(
					$state['issues'],
					function ( $iss ) use ( $issue_id ) {
						return empty( $iss['id'] ) || $iss['id'] !== $issue_id;
					}
				)
			);
			mvn_state_write( MVN_Scanner::STATE_KEY, $state );
		}

		return true;
	}

	/**
	 * Fix every issue of a given action type, or all.
	 *
	 * @param string $action_filter '' | clean | delete_htaccess | quarantine_delete | quarantine
	 * @param int    $limit Max items per call (for AJAX chunking).
	 * @return array {fixed:int, failed:int, remaining:int, errors:[]}
	 */
	public static function fix_batch( $action_filter = '', $limit = 15 ) {
		$issues = MVN_Scanner::get_issues();
		$fixed  = 0;
		$failed = 0;
		$errors = array();
		$kept   = array();

		foreach ( $issues as $issue ) {
			if ( $fixed + $failed >= $limit ) {
				$kept[] = $issue;
				continue;
			}
			if ( $action_filter && ( empty( $issue['action'] ) || $issue['action'] !== $action_filter ) ) {
				$kept[] = $issue;
				continue;
			}
			$r = self::apply( $issue );
			if ( is_wp_error( $r ) ) {
				$failed++;
				$errors[] = $issue['rel'] . ': ' . $r->get_error_message();
				$kept[]   = $issue; // keep so user can retry
			} else {
				$fixed++;
			}
		}

		update_option( MVN_OPTION_ISSUES, $kept, false );
		return array(
			'fixed'     => $fixed,
			'failed'    => $failed,
			'remaining' => count( $kept ),
			'errors'    => $errors,
		);
	}

	/**
	 * Apply the remediation for one issue.
	 */
	private static function apply( $issue ) {
		$rel    = isset( $issue['rel'] ) ? $issue['rel'] : '';
		$action = isset( $issue['action'] ) ? $issue['action'] : 'quarantine';
		$abs    = mvn_abs_path( $rel );

		if ( ! $abs ) {
			return new WP_Error( 'bad_path', 'مسیر نامعتبر.' );
		}

		// Never touch this plugin's own files or wp-config.php via cleaner.
		if ( mvn_is_self_plugin_path( $rel ) ) {
			return new WP_Error( 'protected', 'فایل‌های خود پلاگین آنتی‌ویروس قابل ویرایش از این مسیر نیستند.' );
		}
		if ( 'wp-config.php' === $rel ) {
			return new WP_Error( 'protected', 'wp-config.php محافظت شده است — دستی بررسی کنید.' );
		}

		switch ( $action ) {
			case 'delete_htaccess':
				return self::delete_file( $rel, $abs, 'rogue_htaccess' );

			case 'quarantine_delete':
				return self::delete_file( $rel, $abs, isset( $issue['sig'] ) ? $issue['sig'] : 'malware' );

			case 'quarantine':
				if ( ! is_file( $abs ) ) {
					return true; // already gone
				}
				$id = MVN_Quarantine::store( $rel, array( 'reason' => isset( $issue['sig'] ) ? $issue['sig'] : 'malware', 'issue' => $issue ) );
				if ( ! $id ) {
					return new WP_Error( 'quarantine_fail', 'قرنطینه ناموفق بود.' );
				}
				mvn_log( "Quarantined (kept on disk): {$rel}" );
				return true;

			case 'clean':
			default:
				return self::clean_file( $rel, $abs, $issue );
		}
	}

	/**
	 * Quarantine then delete a file.
	 */
	private static function delete_file( $rel, $abs, $reason ) {
		if ( ! is_file( $abs ) ) {
			return true;
		}
		$id = MVN_Quarantine::store( $rel, array( 'reason' => $reason ) );
		if ( ! $id ) {
			return new WP_Error( 'quarantine_fail', 'قبل از حذف، قرنطینه ناموفق بود.' );
		}
		if ( ! @unlink( $abs ) ) {
			return new WP_Error( 'unlink_fail', 'حذف فایل ناموفق بود (سطح دسترسی؟).' );
		}
		mvn_log( "Deleted: {$rel} (quarantine={$id})" );
		return true;
	}

	/**
	 * Strip injected malware from a file using clean rules.
	 */
	private static function clean_file( $rel, $abs, $issue ) {
		if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return new WP_Error( 'missing', 'فایل وجود ندارد.' );
		}
		$original = @file_get_contents( $abs );
		if ( false === $original ) {
			return new WP_Error( 'read_fail', 'خواندن فایل ناموفق.' );
		}

		$cleaned = $original;
		$rules   = mvn_clean_rules();
		$hits    = 0;
		foreach ( $rules as $pattern => $replacement ) {
			$new = @preg_replace( $pattern, $replacement, $cleaned, -1, $count );
			if ( null !== $new && is_string( $new ) && $count > 0 ) {
				$cleaned = $new;
				$hits   += $count;
			}
		}

		// Extra: strip a leading malware PHP preamble (common prepend injector).
		// Pattern: php open tag + hex comment + base64 var + eval, then real content.
		$stripped = preg_replace(
			'/^\x3c\x3fphp\s*(?:\/\*[^*]*\*\/\s*)*(?:(?:\$[a-zA-Z0-9_]+\s*=\s*[\'"][A-Za-z0-9+\/=]{40,}[\'"]\s*;\s*)|(?:(?:@\s*)?(?:eval|assert)\s*\([^;]+\)\s*;\s*)){1,8}(?:\x3f\x3e\s*)?/s',
			"\x3c\x3fphp\n",
			$cleaned,
			1,
			$pre_count
		);
		if ( is_string( $stripped ) && $pre_count > 0 ) {
			$cleaned = $stripped;
			$hits   += $pre_count;
		}

		// Collapse leftover empty PHP open/close tag pairs.
		$cleaned = preg_replace( '/\x3c\x3fphp\s*\x3f\x3e\s*/', '', $cleaned );

		if ( 0 === $hits || $cleaned === $original ) {
			// Could not auto-clean — quarantine the whole file instead.
			$id = MVN_Quarantine::store( $rel, array( 'reason' => 'uncleanable:' . ( isset( $issue['sig'] ) ? $issue['sig'] : 'unknown' ), 'issue' => $issue ) );
			if ( ! $id ) {
				return new WP_Error( 'uncleanable', 'کد تزریقی قابل حذف خودکار نبود — قرنطینه هم ناموفق بود.' );
			}
			mvn_log( "Could not auto-clean {$rel}; quarantined as {$id}" );
			return new WP_Error( 'uncleanable', 'کد قابل حذف خودکار نبود؛ فایل قرنطینه شد. بررسی دستی توصیه می‌شود.' );
		}

		// Backup then write.
		$id = MVN_Quarantine::store( $rel, array( 'reason' => 'pre-clean-backup', 'issue' => $issue ) );
		if ( ! $id ) {
			return new WP_Error( 'backup_fail', 'پشتیبان‌گیری قبل از پاکسازی ناموفق بود.' );
		}

		$ok = @file_put_contents( $abs, $cleaned );
		if ( false === $ok ) {
			return new WP_Error( 'write_fail', 'نوشتن فایل پاکسازی‌شده ناموفق بود.' );
		}
		mvn_log( "Cleaned: {$rel} (hits={$hits}, backup={$id})" );
		return true;
	}
}
