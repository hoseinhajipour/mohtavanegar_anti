<?php
/**
 * Malware signature library.
 *
 * Each signature:
 *  - id       unique key
 *  - label    human label (shown in UI)
 *  - severity critical | warning | info
 *  - pattern  PCRE regex
 *  - scope    php | js | htaccess | any
 *  - clean    'statement' (auto-removable chunk) | 'block' (whole php/js block) | 'none' (manual/quarantine)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function mvn_signatures() {
	return array(

		// ---------- Execution / obfuscation (PHP) ----------
		array(
			'id'       => 'eval_decoder',
			'label'    => 'eval + رمزگشای (base64/gzinflate/rot13)',
			'severity' => 'critical',
			'pattern'  => '/\b(eval|assert)\s*\(\s*(?:\/\*[^*]*\*\/\s*)*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\(/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'eval_request',
			'label'    => 'اجرای مستقیم ورودی کاربر (eval/assert روی $_GET/$_POST)',
			'severity' => 'critical',
			'pattern'  => '/\b(eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'nested_decoders',
			'label'    => 'رمزگشاهای تودرتو (obfuscation)',
			'severity' => 'critical',
			'pattern'  => '/\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'preg_replace_e',
			'label'    => 'preg_replace با مدیفایر /e (اجرای کد)',
			'severity' => 'critical',
			'pattern'  => '/preg_replace\s*\(\s*[\'"][^\'"]*\/[a-z]*e[a-z]*[\'"]/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'create_function',
			'label'    => 'create_function (کد اجرایی مبهم)',
			'severity' => 'warning',
			'pattern'  => '/\bcreate_function\s*\(/i',
			'scope'    => 'php',
			'clean'    => 'none',
		),
		array(
			'id'       => 'shell_exec_request',
			'label'    => 'اجرای دستور سیستمی از ورودی کاربر',
			'severity' => 'critical',
			'pattern'  => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'hex_include',
			'label'    => 'include با مسیر hex مبهم‌سازی‌شده',
			'severity' => 'critical',
			'pattern'  => '/@?\b(?:include|require)(?:_once)?\s*\(?\s*["\'](?:\\\\x[0-9a-f]{2}){4,}/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'long_base64_blob',
			'label'    => 'بلوک طولانی base64 (احتمال payload رمزشده)',
			'severity' => 'warning',
			'pattern'  => '/[\'"][A-Za-z0-9+\/]{250,}={0,2}[\'"]/',
			'scope'    => 'php',
			'clean'    => 'none',
		),
		array(
			'id'       => 'hex_string_chain',
			'label'    => 'رشته hex طولانی (\\x41\\x42...)',
			'severity' => 'warning',
			'pattern'  => '/(?:\\\\x[0-9a-f]{2}){30,}/i',
			'scope'    => 'php',
			'clean'    => 'none',
		),
		array(
			'id'       => 'chr_chain',
			'label'    => 'زنجیره chr() برای ساخت رشته مخفی',
			'severity' => 'warning',
			'pattern'  => '/\bchr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(/i',
			'scope'    => 'php',
			'clean'    => 'none',
		),
		array(
			'id'       => 'globals_obfuscation',
			'label'    => 'استفاده مبهم از $GLOBALS با کلید رمزشده',
			'severity' => 'warning',
			'pattern'  => '/\$GLOBALS\s*\[\s*[\'"][A-Za-z0-9+\/=]{16,}[\'"]\s*\]/',
			'scope'    => 'php',
			'clean'    => 'none',
		),
		array(
			'id'       => 'variable_variables_eval',
			'label'    => 'متغیرهای داینامیک + eval',
			'severity' => 'critical',
			'pattern'  => '/\$\$?[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
			'scope'    => 'php',
			'clean'    => 'statement',
		),

		// ---------- Known webshells ----------
		array(
			'id'       => 'webshell_markers',
			'label'    => 'امضای وب‌شل شناخته‌شده (c99/r57/WSO/FilesMan/b374k)',
			'severity' => 'critical',
			'pattern'  => '/\b(c99shell|r57shell|FilesMan|b374k|weevely|WSOshell|wso_version|Mini Shell|IndoXploit|AnonymousFox|alfa-shell|alfacgiapi)\b/i',
			'scope'    => 'php',
			'clean'    => 'none',
		),
		array(
			'id'       => 'php_upload_in_uploads',
			'label'    => 'آپلودر مخرب (move_uploaded_file بدون اعتبارسنجی)',
			'severity' => 'warning',
			'pattern'  => '/move_uploaded_file\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
			'scope'    => 'php',
			'clean'    => 'none',
		),

		// ---------- Classic WP injection wrappers ----------
		array(
			'id'       => 'prepend_wrapper',
			'label'    => 'بلوک تزریق‌شده با کامنت/hex در ابتدای فایل',
			'severity' => 'critical',
			'pattern'  => '/\A\s*<\?php\s*(?:\/\*\s*[a-f0-9]{16,}\s*\*\/|\/\/\s*[a-f0-9]{16,}|\$[a-zA-Z0-9_]+\s*=\s*[\'"][A-Za-z0-9+\/=]{100,})/i',
			'scope'    => 'php',
			'clean'    => 'block',
		),
		array(
			'id'       => 'error_reporting_eval_combo',
			'label'    => 'ترکیب error_reporting(0)+eval (هدر بدافزار)',
			'severity' => 'critical',
			'pattern'  => '/error_reporting\s*\(\s*0\s*\)\s*;[^}]{0,400}?\b(eval|assert)\s*\(/is',
			'scope'    => 'php',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'set_time_limit_shell',
			'label'    => 'set_time_limit + md5 password (پترن وب‌شل)',
			'severity' => 'critical',
			'pattern'  => '/set_time_limit\s*\(\s*0\s*\)[\s\S]{0,300}?md5\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
			'scope'    => 'php',
			'clean'    => 'none',
		),

		// ---------- JavaScript injections ----------
		array(
			'id'       => 'js_unescape',
			'label'    => 'document.write(unescape(...)) تزریق JS',
			'severity' => 'critical',
			'pattern'  => '/document\.write\s*\(\s*unescape\s*\(/i',
			'scope'    => 'js',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'js_fromcharcode',
			'label'    => 'String.fromCharCode طولانی (JS مبهم)',
			'severity' => 'warning',
			'pattern'  => '/String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){12,}/i',
			'scope'    => 'js',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'js_atob_eval',
			'label'    => 'eval(atob(...)) در JS',
			'severity' => 'critical',
			'pattern'  => '/\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i',
			'scope'    => 'js',
			'clean'    => 'statement',
		),
		array(
			'id'       => 'hidden_iframe',
			'label'    => 'iframe مخفی (تزریق تبلیغات/بدافزار)',
			'severity' => 'critical',
			'pattern'  => '/<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'"]?0[\'"]?\s|height\s*=\s*[\'"]?0[\'"]?\s)[^>]*>/i',
			'scope'    => 'any',
			'clean'    => 'block',
		),
		array(
			'id'       => 'suspicious_script_src',
			'label'    => 'اسکریپت خارجی مشکوک (دامنه تصادفی)',
			'severity' => 'warning',
			'pattern'  => '/<script[^>]+src\s*=\s*[\'"]https?:\/\/(?:[a-z0-9]{12,}\.(?:top|xyz|club|icu|buzz|site|online)\/)/i',
			'scope'    => 'any',
			'clean'    => 'block',
		),

		// ---------- .htaccess malware ----------
		array(
			'id'       => 'ht_auto_prepend',
			'label'    => 'htaccess با auto_prepend_file (اجرای بدافزار)',
			'severity' => 'critical',
			'pattern'  => '/php_value\s+auto_prepend_file|php_flag\s+auto_prepend_file|auto_prepend_file\s+\S+/i',
			'scope'    => 'htaccess',
			'clean'    => 'none',
		),
		array(
			'id'       => 'ht_sethandler_php',
			'label'    => 'htaccess با SetHandler برای اجرای PHP در پوشه غیرمجاز',
			'severity' => 'critical',
			'pattern'  => '/SetHandler\s+(?:application\/x-httpd-php|php[0-9]*-script)/i',
			'scope'    => 'htaccess',
			'clean'    => 'none',
		),
		array(
			'id'       => 'ht_addhandler_ext',
			'label'    => 'htaccess با AddHandler روی پسوند تصویر (اجرای PHP جاسازی‌شده)',
			'severity' => 'critical',
			'pattern'  => '/Add(?:Handler|Type)\s+[^\n]*(?:\.ico|\.jpg|\.jpeg|\.png|\.gif|\.webp)/i',
			'scope'    => 'htaccess',
			'clean'    => 'none',
		),
		array(
			'id'       => 'ht_rewrite_payload',
			'label'    => 'RewriteRule مشکوک به فایل payload',
			'severity' => 'warning',
			'pattern'  => '/RewriteRule\s+[^\n]*\.(?:ico|jpg|png|gif)\s*$/im',
			'scope'    => 'htaccess',
			'clean'    => 'none',
		),
	);
}

/**
 * Patterns the cleaner can strip automatically (statement-level), ordered.
 * These must be conservative: only match code that is unambiguously malicious.
 */
function mvn_clean_rules() {
	return array(
		// eval(base64_decode(...)); and friends — full statement until first `;` after closing parens.
		'/[ \t]*(?:@\s*)?\b(?:eval|assert)\s*\(\s*(?:\/\*[^*]*\*\/\s*)*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\([^;]*\)\s*\)\s*;/i' => "\n",
		// eval($_POST[...]);
		'/[ \t]*(?:@\s*)?\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)[^;]*\)\s*;/i' => "\n",
		// system/exec/shell_exec from request
		'/[ \t]*\b(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)[^;]*\)\s*;/i' => "\n",
		// variable function from request: $x($_GET[..]);
		'/[ \t]*\$\$?[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)[^;]*\)\s*;/i' => "\n",
		// include with hex-obfuscated path
		'/[ \t]*@?\b(?:include|require)(?:_once)?\s*\(?\s*["\'](?:\\\\x[0-9a-f]{2}){4,}[^"\']*["\']\s*\)?\s*;/i' => "\n",
		// preg_replace with /e modifier executing request data
		'/[ \t]*\bpreg_replace\s*\(\s*[\'"][^\'"]*\/[a-z]*e[a-z]*[\'"]\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)[^;]*\)\s*;/i' => "\n",
		// JS: document.write(unescape(...));
		'/[ \t]*document\.write\s*\(\s*unescape\s*\([^;]*\)\s*\)\s*;?/i' => "\n",
		// JS: eval(atob(...));
		'/[ \t]*\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\([^;]*\)\s*\)\s*;?/i' => "\n",
		// hidden iframes
		'/[ \t]*<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'"]?0[\'"]?)[^>]*>.*?<\/iframe>[ \t]*/is' => "\n",
	);
}
