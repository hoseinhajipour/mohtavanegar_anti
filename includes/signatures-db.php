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
	return array( 'options', 'posts', 'postmeta', 'users', 'usermeta' );
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
	if ( preg_match( '/^(?:wp[0-9]?_|class-wp-|wp_cache_|_wp_)/i', $name ) ) {
		return 'نام option شبیه هسته وردپرس اما غیراستاندارد';
	}
	if ( preg_match( '/^[a-f0-9]{32}$/i', $name ) ) {
		return 'نام option تصادفی (md5-like) — الگوی رایج بدافزار';
	}
	if ( preg_match( '/(?:shell|backdoor|eval|base64|hack|malware|c99|r57)/i', $name ) ) {
		return 'نام option حاوی کلمات مشکوک';
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
	$suspicious_login = preg_match( '/(?:\.php|wp-config|adminer|shell|backdoor|^[a-f0-9]{16,}$|wp_[a-f0-9]{6,})/i', $login );
	$suspicious_email   = '' !== $email && ! is_email( $email );
	if ( $suspicious_login ) {
		return 'نام کاربری مشکوک: ' . $login;
	}
	if ( $suspicious_email ) {
		return 'ایمیل نامعتبر برای کاربر: ' . $login;
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
	if ( preg_match( '/(?:\.php|shell|backdoor|^[a-f0-9]{16,}$)/i', $user->user_login ) ) {
		return 'کاربر «' . $user->user_login . '» با دسترسی administrator مشکوک است';
	}
	return false;
}

function mvn_db_heuristic_spam_injection( $table, $row, $column, $content ) {
	if ( ! in_array( $column, array( 'post_content', 'post_title', 'post_excerpt', 'option_value', 'meta_value' ), true ) ) {
		return false;
	}
	if ( strlen( $content ) < 20 ) {
		return false;
	}
	if ( preg_match( '/<script[^>]+src\s*=\s*["\']https?:\/\/(?!' . preg_quote( parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/i', $content ) ) {
		return 'اسکریپت خارجی در محتوا';
	}
	if ( preg_match( '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i', $content ) && ! preg_match( '/youtube\.com|vimeo\.com|google\.com\/maps/i', $content ) ) {
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
	if ( preg_match( '/O:\d+:"(?:stdClass|Exception|ReflectionClass|SplFileObject)"/i', $content ) ) {
		return 'شیء PHP سریالایز با کلاس خطرناک';
	}
	if ( preg_match( '/(?:eval|base64_decode|gzinflate|shell_exec|system\s*\()/i', $content ) ) {
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
