<?php
/**
 * Database-specific malware heuristics (options, posts, users).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Heuristic checks that run on DB rows (not PCRE signature library).
 *
 * @return array[] {id, label, severity, callback}
 */
function mvn_db_heuristics() {
	return apply_filters(
		'mvn_db_heuristics',
		array(
			array(
				'id'       => 'db_rogue_option_name',
				'label'    => 'نام option مشکوک (پنهان‌سازی بدافزار)',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_rogue_option_name',
			),
			array(
				'id'       => 'db_malware_tracker_option',
				'label'    => 'option ردیابی بدافزار (xdav / _pre_user_id)',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_malware_tracker_option',
			),
			array(
				'id'       => 'db_malware_tracker_usermeta',
				'label'    => 'usermeta ردیابی بدافزار (_wps_sig / _adm_key)',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_malware_tracker_usermeta',
			),
			array(
				'id'       => 'db_hidden_admin',
				'label'    => 'کاربر ادمین مشکوک / پنهان',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_hidden_admin',
			),
			array(
				'id'       => 'db_admin_capability',
				'label'    => 'ارتقای دسترسی ادمین در usermeta',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_admin_capability',
			),
			array(
				'id'       => 'db_spam_injection',
				'label'    => 'لینک/اسکریپت اسپم در محتوا',
				'severity' => 'warning',
				'callback' => 'mvn_db_heuristic_spam_injection',
			),
			array(
				'id'       => 'db_serialized_shell',
				'label'    => 'شیء سریالایز PHP مشکوک',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_serialized_shell',
			),
			array(
				'id'       => 'db_cron_injection',
				'label'    => 'کد مخرب در wp-cron',
				'severity' => 'critical',
				'callback' => 'mvn_db_heuristic_cron_injection',
			),
		)
	);
}

/**
 * Option names that must never be auto-deleted.
 */
function mvn_db_protected_options() {
	return apply_filters(
		'mvn_db_protected_options',
		array(
			'siteurl',
			'home',
			'blogname',
			'blogdescription',
			'admin_email',
			'users_can_register',
			'start_of_week',
			'posts_per_page',
			'date_format',
			'time_format',
			'active_plugins',
			'template',
			'stylesheet',
			'current_theme',
			'cron',
			'wp_user_roles',
			'permalink_structure',
			'category_base',
			'tag_base',
			'upload_path',
			'upload_url_path',
			'db_version',
			'initial_db_version',
			'wp_db_version',
			'rewrite_rules',
			'auth_key',
			'secure_auth_key',
			'logged_in_key',
			'nonce_key',
			'auth_salt',
			'secure_auth_salt',
			'logged_in_salt',
			'nonce_salt',
			// Core options that look "wp_*" but are legitimate (seen as FPs on live sites).
			'wp_page_for_privacy_policy',
			'wp_attachment_pages_enabled',
			'wp_calendar_block_has_published_posts',
			'wp_force_deactivated_plugins',
			'wp_notes_notify',
			'WPLANG',
			'stylesheet_root',
			'template_root',
			'theme_switched',
			'sidebars_widgets',
			'widget_block',
			'can_compress_scripts',
			'finished_splitting_shared_terms',
			'recently_activated',
			'uninstall_plugins',
			'auto_update_core_major',
			'auto_update_core_minor',
			'auto_update_core_dev',
			'auto_plugin_theme_update_emails',
			'wp_plugin_dependencies',
		)
	);
}

function mvn_db_max_value_bytes() {
	return (int) apply_filters( 'mvn_db_scan_max_value_bytes', 524288 );
}

function mvn_db_chunk_size() {
	return (int) apply_filters( 'mvn_db_scan_chunk_size', 35 );
}

function mvn_db_sub_phases() {
	$phases = array( 'options', 'posts', 'postmeta', 'comments', 'commentmeta', 'termmeta', 'users', 'usermeta' );
	if ( is_multisite() ) {
		$phases[] = 'sitemeta';
	}
	return $phases;
}

/**
 * Known-benign option names / prefixes (plugin settings, caches, Freemius, etc.).
 * These must not be signature-scanned — clean rules cannot safely rewrite them.
 */
function mvn_db_benign_option_patterns() {
	return apply_filters(
		'mvn_db_benign_option_patterns',
		array(
			'/^_transient_/',
			'/^_site_transient_/',
			'/^revslider/i',
			'/^rs[_-]/i',
			'/^fs_/i',
			'/^woocommerce_/i',
			'/^wc_/i',
			'/^woodmart/i',
			'/^elementor_/i',
			'/^_elementor_/i',
			'/^wpr_/i',
			'/^wp_rocket/i',
			'/^litespeed_/i',
			'/^external_updates-/i',
			'/^rtl_/i',
			'/^acf_/i',
			'/^rank_math/i',
			'/^yoast/i',
			'/^wpseo/i',
			'/^wordfence/i',
			'/^wf/i',
			'/^updraft/i',
			'/^jetpack_/i',
			'/^gravityforms/i',
			'/^gf_/i',
			'/^redux_/i',
			'/^kirki_/i',
			'/^widget_/i',
			'/^theme_mods_/i',
			'/^sidebars_widgets$/i',
			'/^cron$/i',
			'/^rewrite_rules$/i',
			'/^can_compress_scripts$/i',
			'/^recently_edited$/i',
			'/^auto_updater/i',
			'/^_site_transient_update_/i',
			'/^_transient_plugin_/i',
			'/^_transient_timeout_/i',
			'/^_site_transient_timeout_/i',
		)
	);
}

/**
 * @param string $name Option name.
 * @return bool
 */
function mvn_db_is_benign_option( $name ) {
	$name = (string) $name;
	if ( '' === $name ) {
		return false;
	}
	if ( in_array( $name, mvn_db_protected_options(), true ) ) {
		return true;
	}
	foreach ( mvn_db_benign_option_patterns() as $pattern ) {
		if ( @preg_match( $pattern, $name ) ) {
			return true;
		}
	}
	return (bool) apply_filters( 'mvn_db_is_benign_option', false, $name );
}

/**
 * Meta keys that are almost always plugin config (high FP rate for file signatures).
 */
function mvn_db_is_benign_meta_key( $key ) {
	$key = (string) $key;
	if ( '' === $key ) {
		return false;
	}
	$patterns = apply_filters(
		'mvn_db_benign_meta_key_patterns',
		array(
			'/^_elementor/',
			'/^_wp_/',
			'/^_woocommerce/',
			'/^_wc_/',
			'/^_oembed/',
			'/^_menu_item/',
			'/^field_/',
			'/^_field_/',
			'/^rank_math/',
			'/^_yoast/',
		)
	);
	foreach ( $patterns as $pattern ) {
		if ( @preg_match( $pattern, $key ) ) {
			return true;
		}
	}
	return (bool) apply_filters( 'mvn_db_is_benign_meta_key', false, $key );
}

function mvn_db_heuristic_rogue_option_name( $table, $row, $column, $content ) {
	if ( 'options' !== $table || 'option_name' !== $column ) {
		return false;
	}
	$name = isset( $row['option_name'] ) ? (string) $row['option_name'] : $content;
	if ( '' === $name ) {
		return false;
	}
	if ( in_array( $name, mvn_db_protected_options(), true ) ) {
		return false;
	}
	if ( mvn_db_is_benign_option( $name ) ) {
		return false;
	}
	// Pure md5-like option names (common malware stash).
	if ( preg_match( '/^[a-f0-9]{32}$/i', $name ) ) {
		return 'نام option تصادفی (md5-like) — الگوی رایج بدافزار';
	}
	// Fake core-looking names: wp_ + random hex / class-wp- obfuscation — NOT all wp_* (core uses many).
	if ( preg_match( '/^(?:wp[0-9]?_[a-f0-9]{8,}|class-wp-[a-f0-9]{6,}|wp_cache_[a-f0-9]{8,})$/i', $name ) ) {
		return 'نام option شبیه هسته وردپرس اما غیراستاندارد';
	}
	// Keyword hits — skip short legitimate substrings already covered by protected list.
	if ( preg_match( '/(?:shell|backdoor|c99|r57|xdav[-_]?tracker|webshell|hack_file|^hack_)/i', $name ) ) {
		return 'نام option حاوی کلمات مشکوک';
	}
	return false;
}

/**
 * Tracker options used by xdav-tracker / wp-security-helper / wp-compat families.
 */
function mvn_db_heuristic_malware_tracker_option( $table, $row, $column, $content ) {
	if ( 'options' !== $table || 'option_name' !== $column ) {
		return false;
	}
	$name = isset( $row['option_name'] ) ? (string) $row['option_name'] : $content;
	if ( '' === $name || in_array( $name, mvn_db_protected_options(), true ) ) {
		return false;
	}
	$known = class_exists( 'MVN_Ghost_Plugins' ) ? MVN_Ghost_Plugins::malware_option_names() : array( '_pre_user_id' );
	if ( in_array( $name, $known, true ) ) {
		return 'option ردیابی بدافزار شناخته‌شده: ' . $name;
	}
	if ( preg_match( '/(?:^_?pre_user_id$|xdav|security[-_]?helper|wp[-_]?compat|zonal[-_]?runner)/i', $name ) ) {
		return 'option مشکوک خانواده بک‌دور مخفی: ' . $name;
	}
	return false;
}

/**
 * Usermeta keys used by Hidden Admin Toolkit / fake plugin families (Imunify IoCs).
 */
function mvn_db_heuristic_malware_tracker_usermeta( $table, $row, $column, $content ) {
	if ( 'usermeta' !== $table || 'meta_key' !== $column ) {
		return false;
	}
	$key = isset( $row['meta_key'] ) ? (string) $row['meta_key'] : $content;
	$bad = array(
		'_wp_ui_render_cfg',
		'_wp_cache_hash',
		'_wps_sig',
		'_sys_token',
		'_bk_hash',
		'_adm_key',
		'_wp_sys_hash',
		'_stk_sig',
	);
	if ( in_array( $key, $bad, true ) ) {
		return 'usermeta ردیابی بدافزار: ' . $key;
	}
	return false;
}

function mvn_db_heuristic_hidden_admin( $table, $row, $column, $content ) {
	if ( 'users' !== $table || 'user_login' !== $column ) {
		return false;
	}
	$login = isset( $row['user_login'] ) ? (string) $row['user_login'] : '';
	$email = isset( $row['user_email'] ) ? (string) $row['user_email'] : '';
	if ( '' === $login ) {
		return false;
	}
	if ( 1 === (int) ( isset( $row['ID'] ) ? $row['ID'] : 0 ) ) {
		return false;
	}
	$suspicious_login = preg_match(
		'/(?:\.php|wp-config|adminer|shell|backdoor|^[a-f0-9]{16,}$|wp_[a-f0-9]{6,}|adminbackup|adm1nlxg1n|support_user|sys_maint|codepapa|helpdesk_?admin)/i',
		$login
	);
	$suspicious_email = '' !== $email && (
		! is_email( $email )
		|| preg_match( '/@(?:wordpress\.org|w\.org)$/i', $email )
	);
	if ( $suspicious_login ) {
		return 'نام کاربری مشکوک: ' . $login;
	}
	if ( $suspicious_email ) {
		return 'ایمیل مشکوک برای کاربر «' . $login . '»: ' . $email;
	}
	return false;
}

function mvn_db_heuristic_admin_capability( $table, $row, $column, $content ) {
	if ( 'usermeta' !== $table || 'meta_value' !== $column ) {
		return false;
	}
	$key = isset( $row['meta_key'] ) ? (string) $row['meta_key'] : '';
	if ( false === strpos( $key, 'capabilities' ) ) {
		return false;
	}
	if ( false === strpos( $content, 'administrator' ) ) {
		return false;
	}
	$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
	if ( 1 === $user_id ) {
		return false;
	}
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return 'کاربر ناشناس با capability ادمین';
	}
	if ( preg_match( '/(?:\.php|shell|backdoor|^[a-f0-9]{16,}$|adminbackup|adm1nlxg1n)/i', $user->user_login ) ) {
		return 'کاربر «' . $user->user_login . '» با دسترسی administrator مشکوک است';
	}
	return false;
}

function mvn_db_heuristic_spam_injection( $table, $row, $column, $content ) {
	// Spam heuristics target post content, not plugin option blobs.
	if ( ! in_array( $column, array( 'post_content', 'post_title', 'post_excerpt' ), true ) ) {
		return false;
	}
	if ( strlen( $content ) < 20 ) {
		return false;
	}
	if ( preg_match( '/<script[^>]+src\s*=\s*["\']https?:\/\/(?!' . preg_quote( parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/i', $content ) ) {
		return 'اسکریپت خارجی در محتوا';
	}
	// WordPress oEmbed uses class="wp-embedded-content" iframes — not spam.
	if ( preg_match( '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i', $content )
		&& ! preg_match( '/youtube\.com|vimeo\.com|google\.com\/maps|wp-embedded-content|data-secret=/i', $content ) ) {
		return 'iframe خارجی مشکوک';
	}
	if ( preg_match( '/\b(?:viagra|cialis|casino|porn|xxx|payday)\b/i', $content ) ) {
		return 'کلمات اسپم در محتوا';
	}
	return false;
}

function mvn_db_heuristic_serialized_shell( $table, $row, $column, $content ) {
	if ( ! in_array( $column, array( 'option_value', 'meta_value' ), true ) ) {
		return false;
	}
	if ( ! is_serialized( $content ) ) {
		return false;
	}

	// WordPress update / cache transients + common plugin option blobs — not malware.
	if ( 'options' === $table && ! empty( $row['option_name'] ) ) {
		$name = (string) $row['option_name'];
		if ( 0 === strpos( $name, '_transient_' ) || 0 === strpos( $name, '_site_transient_' ) ) {
			return false;
		}
		if ( preg_match( '/^(?:revslider|elementor|woocommerce|rank_math|litespeed|wpo_|fs_|wpseo)/i', $name ) ) {
			return false;
		}
	}

	// stdClass alone is benign; dangerous gadget classes are the real risk.
	if ( preg_match( '/O:\d+:"(?:Exception|ReflectionClass|ReflectionFunction|SplFileObject|PDO|Phar)"/i', $content ) ) {
		return 'شیء PHP سریالایز با کلاس خطرناک';
	}
	if ( preg_match( '/(?:eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\(|system\s*\()/i', $content ) ) {
		return 'کد اجرایی داخل داده سریالایز';
	}
	return false;
}

function mvn_db_heuristic_cron_injection( $table, $row, $column, $content ) {
	if ( 'options' !== $table || 'option_value' !== $column ) {
		return false;
	}
	$name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
	if ( 'cron' !== $name ) {
		return false;
	}
	if ( preg_match( '/(?:eval|base64_decode|gzinflate|shell_exec|passthru|assert\s*\()/i', $content ) ) {
		return 'کد PHP مخرب در آرایه cron';
	}
	return false;
}
