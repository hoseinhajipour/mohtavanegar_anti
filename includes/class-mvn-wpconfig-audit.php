<?php
/**
 * Read-only wp-config.php security audit.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_WPConfig_Audit {

	/**
	 * Locate the active config file.
	 *
	 * @return string|false
	 */
	private static function path() {
		if ( is_file( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$parent = dirname( rtrim( ABSPATH, '/\\' ) ) . '/wp-config.php';
		return is_file( $parent ) ? $parent : false;
	}

	/**
	 * Return findings only; this class never writes configuration.
	 *
	 * @return array[]
	 */
	public static function audit() {
		$path = self::path();
		if ( ! $path || ! is_readable( $path ) ) {
			return array();
		}
		$content  = (string) @file_get_contents( $path );
		$rel      = mvn_rel_path( $path );
		$findings = array();
		$rules    = array(
			array( 'wpconfig_execution', '/\b(?:eval|assert)\s*\(|(?:base64_decode|gzinflate)\s*\(/i', 94, 'اجرای پویا/decoder در wp-config.php' ),
			array( 'wpconfig_prepend', '/auto_(?:pre|ap)pend_file/i', 98, 'دستور prepend/append در wp-config.php' ),
			array( 'wpconfig_external_include', '/\b(?:include|require)(?:_once)?\s*\(?\s*[\'"](?:https?:|phar:|zip:|\/tmp\/|[A-Za-z]:\\\\)/i', 96, 'include بیرونی/غیرمنتظره در wp-config.php' ),
			array( 'wpconfig_debug_display', '/define\s*\(\s*[\'"]WP_DEBUG_DISPLAY[\'"]\s*,\s*true\s*\)/i', 68, 'نمایش خطا در محیط عمومی فعال است' ),
		);
		foreach ( $rules as $rule ) {
			if ( preg_match( $rule[1], $content, $match, PREG_OFFSET_CAPTURE ) ) {
				$findings[] = array(
					'rel'        => $rel,
					'sig'        => $rule[0],
					'label'      => $rule[3],
					'severity'   => $rule[2] >= 95 ? 'critical' : 'warning',
					'detail'     => 'ممیزی فقط‌خواندنی؛ wp-config.php هرگز خودکار ویرایش نمی‌شود.',
					'action'     => 'manual_review',
					'confidence' => $rule[2],
					'source'     => 'wpconfig',
					'snippet'    => substr( $content, max( 0, $match[0][1] - 60 ), 180 ),
					'evidence'   => array( array( 'engine' => 'wpconfig', 'signal' => $rule[0] ) ),
				);
			}
		}
		$salts = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
		$weak  = 0;
		foreach ( $salts as $salt ) {
			if ( ! preg_match( '/define\s*\(\s*[\'"]' . $salt . '[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/', $content, $m ) || strlen( $m[1] ) < 48 || false !== stripos( $m[1], 'unique phrase' ) ) {
				$weak++;
			}
		}
		if ( $weak ) {
			$findings[] = array(
				'rel' => $rel, 'sig' => 'wpconfig_weak_salts', 'label' => 'کلیدهای امنیتی ناقص/ضعیف',
				'severity' => 'warning', 'detail' => $weak . ' salt/key نیازمند بازبینی است.',
				'action' => 'manual_review', 'confidence' => 75, 'source' => 'wpconfig',
				'evidence' => array( array( 'engine' => 'wpconfig', 'signal' => 'weak_salts' ) ),
			);
		}
		return $findings;
	}
}
