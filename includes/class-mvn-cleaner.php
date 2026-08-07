<?php
/**
 * Cleaner / Fix engine — strip injected malware, quarantine, delete.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Cleaner {

	/**
	 * Destructive file actions that mutate plugin files on disk.
	 */
	private static function destructive_actions() {
		return array( 'quarantine_delete', 'quarantine', 'clean', 'delete_htaccess' );
	}

	/**
	 * Active plugins that would be affected by upcoming fix operations.
	 *
	 * @param string      $action_filter Batch filter (empty = all fixable).
	 * @param string|null $issue_id      Optional single issue id.
	 * @return array[] List of {file, slug, name, count}.
	 */
	public static function affected_active_plugins( $action_filter = '', $issue_id = null ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$issues = MVN_Scanner::get_issues();
		if ( $issue_id ) {
			$issues = array_values(
				array_filter(
					$issues,
					function ( $iss ) use ( $issue_id ) {
						return isset( $iss['id'] ) && $iss['id'] === $issue_id;
					}
				)
			);
		}

		$skip_actions   = array( 'core_repair', 'db_review' );
		$destructive    = self::destructive_actions();
		$folder_to_meta = array();

		foreach ( get_plugins() as $file => $data ) {
			$folder = dirname( $file );
			if ( '.' === $folder ) {
				// Single-file plugin in plugins root (e.g. hello.php).
				$folder_to_meta[ basename( $file ) ] = array(
					'file' => $file,
					'name' => isset( $data['Name'] ) ? $data['Name'] : $file,
					'single' => true,
				);
				continue;
			}
			if ( ! isset( $folder_to_meta[ $folder ] ) ) {
				$folder_to_meta[ $folder ] = array(
					'file'   => $file,
					'name'   => isset( $data['Name'] ) ? $data['Name'] : $folder,
					'single' => false,
				);
			}
		}

		$hits = array(); // plugin_file => meta+count

		foreach ( $issues as $issue ) {
			$action = isset( $issue['action'] ) ? $issue['action'] : '';
			if ( $action_filter && $action !== $action_filter ) {
				continue;
			}
			if ( ! $action_filter && in_array( $action, $skip_actions, true ) ) {
				continue;
			}
			if ( ! in_array( $action, $destructive, true ) ) {
				continue;
			}

			$rel = isset( $issue['rel'] ) ? str_replace( '\\', '/', $issue['rel'] ) : '';
			if ( '' === $rel || 0 !== strpos( $rel, 'wp-content/plugins/' ) ) {
				continue;
			}
			if ( mvn_is_self_plugin_path( $rel ) ) {
				continue;
			}

			$rest = substr( $rel, strlen( 'wp-content/plugins/' ) );
			$meta = null;
			if ( false !== strpos( $rest, '/' ) ) {
				$folder = strstr( $rest, '/', true );
				if ( isset( $folder_to_meta[ $folder ] ) && empty( $folder_to_meta[ $folder ]['single'] ) ) {
					$meta = $folder_to_meta[ $folder ];
					$meta['slug'] = $folder;
				}
			} else {
				// Single-file plugin path.
				if ( isset( $folder_to_meta[ $rest ] ) ) {
					$meta = $folder_to_meta[ $rest ];
					$meta['slug'] = $rest;
				}
			}

			if ( ! $meta || empty( $meta['file'] ) ) {
				continue;
			}
			if ( ! is_plugin_active( $meta['file'] ) ) {
				continue;
			}

			$key = $meta['file'];
			if ( ! isset( $hits[ $key ] ) ) {
				$hits[ $key ] = array(
					'file'  => $meta['file'],
					'slug'  => $meta['slug'],
					'name'  => $meta['name'],
					'count' => 0,
				);
			}
			$hits[ $key ]['count']++;
		}

		return array_values( $hits );
	}

	/**
	 * Deactivate a list of plugin files (never self).
	 *
	 * @param string[] $plugin_files Plugin basenames (e.g. akismet/akismet.php).
	 * @return array {deactivated:string[], failed:array, skipped:string[]}
	 */
	public static function deactivate_plugins( $plugin_files ) {
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$deactivated = array();
		$failed      = array();
		$skipped     = array();

		foreach ( (array) $plugin_files as $file ) {
			$file = wp_unslash( $file );
			$file = preg_replace( '#\.+#', '.', $file );
			$file = ltrim( str_replace( '\\', '/', (string) $file ), '/' );
			if ( ! $file || false !== strpos( $file, '..' ) ) {
				$failed[] = $file . ': مسیر نامعتبر';
				continue;
			}
			if ( mvn_is_self_plugin_path( 'wp-content/plugins/' . dirname( $file ) . '/' ) || mvn_is_self_plugin_path( 'wp-content/plugins/' . $file ) ) {
				$skipped[] = $file;
				continue;
			}
			if ( ! is_plugin_active( $file ) ) {
				$skipped[] = $file;
				continue;
			}
			deactivate_plugins( $file, true );
			if ( is_plugin_active( $file ) ) {
				$failed[] = $file . ': غیرفعال‌سازی ناموفق';
			} else {
				$deactivated[] = $file;
				mvn_log( 'Deactivated plugin before fix: ' . $file );
			}
		}

		return array(
			'deactivated' => $deactivated,
			'failed'      => $failed,
			'skipped'     => $skipped,
		);
	}

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
		$skipped = 0;
		$errors = array();
		$kept   = array();
		$skip_actions = array( 'core_repair', 'db_review' );

		foreach ( $issues as $issue ) {
			$action = isset( $issue['action'] ) ? $issue['action'] : '';

			if ( $fixed + $failed >= $limit ) {
				$kept[] = $issue;
				continue;
			}

			if ( $action_filter && ( empty( $action ) || $action !== $action_filter ) ) {
				$kept[] = $issue;
				continue;
			}

			if ( ! $action_filter && in_array( $action, $skip_actions, true ) ) {
				$kept[] = $issue;
				$skipped++;
				continue;
			}

			$r = self::apply( $issue );
			if ( is_wp_error( $r ) ) {
				$failed++;
				$errors[] = ( isset( $issue['rel'] ) ? $issue['rel'] : '?' ) . ': ' . $r->get_error_message();
				$kept[]   = $issue;
			} else {
				$fixed++;
			}
		}

		update_option( MVN_OPTION_ISSUES, $kept, false );
		return array(
			'fixed'     => $fixed,
			'failed'    => $failed,
			'skipped'   => $skipped,
			'remaining' => count( $kept ),
			'errors'    => $errors,
		);
	}

	/**
	 * Apply the remediation for one issue.
	 */
	private static function apply( $issue ) {
		$rel    = isset( $issue['rel'] ) ? $issue['rel'] : '';
		$source = isset( $issue['source'] ) ? $issue['source'] : 'file';
		$action = isset( $issue['action'] ) ? $issue['action'] : 'quarantine';

		if ( 'db' === $source || 0 === strpos( $rel, 'db:' ) ) {
			return self::apply_db( $issue );
		}

		$abs = mvn_abs_path( $rel );

		if ( ! $abs ) {
			return new WP_Error( 'bad_path', 'مسیر نامعتبر.' );
		}

		// Core extras may be deleted; selective core restore handled below.
		$is_core = mvn_is_core_path( $rel );
		if ( $is_core && ! in_array( $action, array( 'delete_core_extra', 'core_repair_file' ), true ) ) {
			return new WP_Error( 'protected', 'فایل‌های هسته وردپرس از اینجا ویرایش نمی‌شوند — از «تعمیر هسته» استفاده کنید.' );
		}
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
			case 'delete_core_extra':
				if ( $is_core && 'delete_core_extra' === $action ) {
					// Only extras (not official core paths that appear in allowlist as real files).
					// Extras are files under wp-admin/wp-includes that are NOT in checksum map —
					// still under "core path" prefix, so allow delete here.
					return self::delete_file( $rel, $abs, isset( $issue['sig'] ) ? $issue['sig'] : 'core_extra' );
				}
				return self::delete_file( $rel, $abs, isset( $issue['sig'] ) ? $issue['sig'] : 'malware' );

			case 'core_repair_file':
				return MVN_Core_Repair::repair_one( $rel );

			case 'quarantine':
				// Isolate = move to quarantine (remove live copy).
				$result = MVN_Quarantine::isolate(
					$rel,
					array(
						'reason' => isset( $issue['sig'] ) ? $issue['sig'] : 'malware',
						'issue'  => $issue,
					)
				);
				if ( is_wp_error( $result ) ) {
					return $result;
				}
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
			// Could not auto-clean — isolate (quarantine + remove live file).
			$result = MVN_Quarantine::isolate(
				$rel,
				array(
					'reason' => 'uncleanable:' . ( isset( $issue['sig'] ) ? $issue['sig'] : 'unknown' ),
					'issue'  => $issue,
				)
			);
			if ( is_wp_error( $result ) ) {
				return new WP_Error( 'uncleanable', 'کد تزریقی قابل حذف خودکار نبود — ایزوله هم ناموفق: ' . $result->get_error_message() );
			}
			mvn_log( "Could not auto-clean {$rel}; isolated as {$result}" );
			return new WP_Error( 'uncleanable', 'کد قابل حذف خودکار نبود؛ فایل ایزوله (قرنطینه+حذف) شد. بررسی دستی توصیه می‌شود.' );
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

	/**
	 * Apply remediation for a database finding.
	 *
	 * @return true|WP_Error
	 */
	private static function apply_db( $issue ) {
		$action = isset( $issue['action'] ) ? $issue['action'] : 'db_review';
		$table  = isset( $issue['table'] ) ? $issue['table'] : '';
		$rel    = isset( $issue['rel'] ) ? $issue['rel'] : '';

		switch ( $action ) {
			case 'db_clean':
				return self::db_clean( $issue );

			case 'db_delete_option':
				return self::db_delete_option( $issue );

			case 'db_review':
			default:
				return new WP_Error( 'db_review', 'این مورد دیتابیس نیاز به بررسی دستی دارد (کاربر/option حساس).' );
		}
	}

	private static function db_clean( $issue ) {
		$table  = isset( $issue['table'] ) ? $issue['table'] : '';
		$row_id = isset( $issue['row_id'] ) ? (int) $issue['row_id'] : 0;
		$column = isset( $issue['column'] ) ? $issue['column'] : '';

		if ( ! $table || ! $row_id || ! $column ) {
			return new WP_Error( 'db_bad_issue', 'اطلاعات ردیف دیتابیس ناقص است.' );
		}

		$fetch = self::db_fetch_row( $table, $row_id );
		if ( is_wp_error( $fetch ) ) {
			return $fetch;
		}

		$row      = $fetch['row'];
		$original = isset( $row[ $column ] ) ? (string) $row[ $column ] : '';
		if ( '' === $original ) {
			return new WP_Error( 'db_empty', 'مقدار ستون خالی است.' );
		}

		// Dismiss known false positives instead of failing forever.
		if ( self::db_finding_is_false_positive( $issue, $row, $original ) ) {
			mvn_log( 'DB finding dismissed as false positive: ' . ( isset( $issue['rel'] ) ? $issue['rel'] : '' ) );
			return true;
		}

		// Auto-clean only makes sense for HTML/JS injection in post content.
		if ( ! in_array( $column, array( 'post_content', 'post_excerpt', 'post_title' ), true ) ) {
			return new WP_Error( 'db_review', 'این مورد option/meta قابل پاکسازی خودکار نیست — «امن است» بزنید یا دستی بررسی کنید.' );
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

		// Strip common spam iframes / remote scripts from post content.
		$extra = array(
			'/<iframe[^>]+style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*?<\/iframe>/is' => '',
			'/<iframe[^>]+width\s*=\s*["\']?0["\']?[^>]*>.*?<\/iframe>/is' => '',
			'/<script[^>]+src\s*=\s*["\']https?:\/\/(?!(?:www\.)?(?:youtube|youtu\.be|vimeo|google))[^"\']+["\'][^>]*>\s*<\/script>/is' => '',
		);
		foreach ( $extra as $pattern => $replacement ) {
			$new = @preg_replace( $pattern, $replacement, $cleaned, -1, $count );
			if ( null !== $new && is_string( $new ) && $count > 0 ) {
				$cleaned = $new;
				$hits   += $count;
			}
		}

		if ( 0 === $hits || $cleaned === $original ) {
			return new WP_Error( 'db_uncleanable', 'کد مخرب در دیتابیس قابل حذف خودکار نبود — بررسی دستی لازم است.' );
		}

		$backup_id = MVN_Quarantine::store_text(
			isset( $issue['rel'] ) ? $issue['rel'] : 'db:backup',
			wp_json_encode(
				array(
					'table'  => $table,
					'row_id' => $row_id,
					'column' => $column,
					'before' => $original,
				)
			),
			array(
				'reason' => 'db-pre-clean',
				'issue'  => $issue,
			)
		);
		if ( ! $backup_id ) {
			return new WP_Error( 'db_backup_fail', 'پشتیبان‌گیری قبل از پاکسازی دیتابیس ناموفق بود.' );
		}

		$updated = self::db_update_column( $table, $row_id, $column, $cleaned );
		if ( is_wp_error( $updated ) ) {
			return $updated;
		}

		mvn_log( "DB cleaned: {$table}#{$row_id}.{$column} (hits={$hits})" );
		return true;
	}

	/**
	 * Detect FP findings that should be dismissed (not failed) during db_clean.
	 */
	private static function db_finding_is_false_positive( $issue, $row, $content ) {
		$table = isset( $issue['table'] ) ? $issue['table'] : '';
		if ( 'options' === $table ) {
			$name = isset( $row['option_name'] ) ? $row['option_name'] : '';
			if ( $name && mvn_db_is_benign_option( $name ) ) {
				return true;
			}
			// Opaque serialized plugin data without PHP open tag — not injectable malware.
			if ( function_exists( 'is_serialized' ) && is_serialized( $content ) && false === strpos( $content, '<?php' ) && false === stripos( $content, 'eval(' ) ) {
				return true;
			}
		}
		if ( 'postmeta' === $table && ! empty( $row['meta_key'] ) && mvn_db_is_benign_meta_key( $row['meta_key'] ) ) {
			return true;
		}
		return false;
	}

	private static function db_delete_option( $issue ) {
		global $wpdb;

		$table = isset( $issue['table'] ) ? $issue['table'] : '';
		if ( 'options' !== $table ) {
			return new WP_Error( 'db_protected', 'فقط optionهای مشکوک قابل حذف خودکار هستند.' );
		}

		$row_id = isset( $issue['row_id'] ) ? (int) $issue['row_id'] : 0;
		$fetch  = self::db_fetch_row( 'options', $row_id );
		if ( is_wp_error( $fetch ) ) {
			return $fetch;
		}

		$name = isset( $fetch['row']['option_name'] ) ? $fetch['row']['option_name'] : '';
		if ( ! $name || in_array( $name, mvn_db_protected_options(), true ) ) {
			return new WP_Error( 'db_protected', 'این option محافظت‌شده است و حذف نمی‌شود.' );
		}

		$value = isset( $fetch['row']['option_value'] ) ? $fetch['row']['option_value'] : '';
		$backup_id = MVN_Quarantine::store_text(
			'db:options:' . $name,
			wp_json_encode( array( 'option_name' => $name, 'option_value' => $value ) ),
			array(
				'reason' => 'db-option-delete',
				'issue'  => $issue,
			)
		);
		if ( ! $backup_id ) {
			return new WP_Error( 'db_backup_fail', 'پشتیبان‌گیری option قبل از حذف ناموفق بود.' );
		}

		$deleted = $wpdb->delete( $wpdb->options, array( 'option_id' => $row_id ), array( '%d' ) );
		if ( ! $deleted ) {
			return new WP_Error( 'db_delete_fail', 'حذف option ناموفق بود.' );
		}

		mvn_log( "DB option deleted: {$name} (id={$row_id})" );
		return true;
	}

	private static function db_fetch_row( $table, $row_id ) {
		global $wpdb;

		switch ( $table ) {
			case 'options':
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_id, option_name, option_value FROM {$wpdb->options} WHERE option_id = %d", $row_id ), ARRAY_A );
				break;
			case 'posts':
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT ID, post_title, post_content, post_excerpt, guid FROM {$wpdb->posts} WHERE ID = %d", $row_id ), ARRAY_A );
				break;
			case 'postmeta':
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT meta_id, post_id, meta_key, meta_value FROM {$wpdb->postmeta} WHERE meta_id = %d", $row_id ), ARRAY_A );
				break;
			case 'users':
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT ID, user_login, user_email, user_url, display_name FROM {$wpdb->users} WHERE ID = %d", $row_id ), ARRAY_A );
				break;
			case 'usermeta':
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT umeta_id, user_id, meta_key, meta_value FROM {$wpdb->usermeta} WHERE umeta_id = %d", $row_id ), ARRAY_A );
				break;
			default:
				return new WP_Error( 'db_bad_table', 'جدول نامعتبر.' );
		}

		if ( empty( $row ) ) {
			return new WP_Error( 'db_not_found', 'ردیف دیتابیس یافت نشد.' );
		}

		return array( 'row' => $row );
	}

	private static function db_update_column( $table, $row_id, $column, $value ) {
		global $wpdb;

		$allowed = array(
			'options'  => array( 'option_value' => 'option_id' ),
			'posts'    => array( 'post_content' => 'ID', 'post_title' => 'ID', 'post_excerpt' => 'ID', 'guid' => 'ID' ),
			'postmeta' => array( 'meta_value' => 'meta_id', 'meta_key' => 'meta_id' ),
			'users'    => array( 'user_login' => 'ID', 'user_email' => 'ID', 'user_url' => 'ID', 'display_name' => 'ID' ),
			'usermeta' => array( 'meta_value' => 'umeta_id', 'meta_key' => 'umeta_id' ),
		);

		if ( ! isset( $allowed[ $table ][ $column ] ) ) {
			return new WP_Error( 'db_bad_column', 'ستون غیرمجاز برای ویرایش.' );
		}

		$id_col = $allowed[ $table ][ $column ];
		$tbl    = '';
		switch ( $table ) {
			case 'options':
				$tbl = $wpdb->options;
				break;
			case 'posts':
				$tbl = $wpdb->posts;
				break;
			case 'postmeta':
				$tbl = $wpdb->postmeta;
				break;
			case 'users':
				$tbl = $wpdb->users;
				break;
			case 'usermeta':
				$tbl = $wpdb->usermeta;
				break;
		}

		$ok = $wpdb->update( $tbl, array( $column => $value ), array( $id_col => $row_id ), array( '%s' ), array( '%d' ) );
		if ( false === $ok ) {
			return new WP_Error( 'db_write_fail', 'نوشتن در دیتابیس ناموفق بود.' );
		}
		return true;
	}
}
