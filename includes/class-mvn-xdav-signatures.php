<?php
/**
 * XDav / Zonal Runner multi-signal risk scoring (signature + heuristic).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_XDav_Signatures {

	/**
	 * Filename / slug IoCs.
	 *
	 * @return string[]
	 */
	public static function name_patterns() {
		return apply_filters(
			'mvn_xdav_name_patterns',
			array(
				'/xdav[-_]?tracker/i',
				'/tracker[-_]?user/i',
				'/user[-_]?tracker/i',
				'/zonal[-_]?runner/i',
				'/wp-security-helper/i',
				'/cloudflare[-_]?verif/i',
				'/wp-compat\.php$/i',
			)
		);
	}

	/**
	 * Score a file for XDav-family risk (0–100). Function presence alone is never enough.
	 *
	 * @param string $rel     Relative path.
	 * @param string $content File contents (may be truncated).
	 * @return array{score:int,signals:string[],label:string}
	 */
	public static function score( $rel, $content ) {
		$rel     = str_replace( '\\', '/', (string) $rel );
		$content = (string) $content;
		$signals = array();
		$score   = 0;
		$base    = basename( $rel );

		foreach ( self::name_patterns() as $pattern ) {
			if ( @preg_match( $pattern, $rel ) || @preg_match( $pattern, $base ) ) {
				$signals[] = 'name_ioc';
				$score    += 45;
				break;
			}
		}

		if ( preg_match( '/Plugin\s+Name\s*:\s*[^\n]*(?:xdav|zonal\s*runner|security\s*helper|Fake\s+Cloudflare)/i', $content ) ) {
			$signals[] = 'plugin_header';
			$score    += 35;
		}
		if ( preg_match( '/(?:namespace\s+XDav|class\s+XDav|function\s+xdav_|TrackerD)/i', $content ) ) {
			$signals[] = 'symbol_ioc';
			$score    += 25;
		}
		if ( preg_match( '/all_plugins|show_advanced_plugins|pre_option_active_plugins/i', $content ) ) {
			$signals[] = 'plugin_hiding';
			$score    += 18;
		}
		if ( preg_match( '/wp_insert_user|wp_create_user|set_role\s*\(\s*[\'"]administrator/i', $content ) ) {
			$signals[] = 'admin_create';
			$score    += 15;
		}
		if ( preg_match( '/file_put_contents\s*\([^;]*(?:mu-plugins|plugins\/|xdav|zonal|\.user\.ini|db\.php)/is', $content ) ) {
			$signals[] = 'persistence_write';
			$score    += 28;
		}
		if ( preg_match( '/(?:wp_remote_get|wp_remote_post|curl_exec|file_get_contents)\s*\(\s*[\'"]https?:\/\//i', $content )
			&& preg_match( '/(?:file_put_contents|fwrite|eval|assert)\s*\(/i', $content ) ) {
			$signals[] = 'remote_downloader';
			$score    += 30;
		}
		if ( preg_match( '/\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}/i', $content )
			|| preg_match( '/[\'"]ba[\'"]\s*\.\s*[\'"]se64_decode[\'"]/i', $content ) ) {
			$signals[] = 'obfuscation';
			$score    += 12;
		}
		// Lone base64_decode / eval without other signals: small bump only.
		if ( preg_match( '/\beval\s*\(/i', $content ) ) {
			$score += 8;
			$signals[] = 'eval';
		}
		if ( preg_match( '/\bbase64_decode\s*\(/i', $content ) && count( $signals ) < 2 ) {
			$score += 3;
		}

		$score = max( 0, min( 99, $score ) );
		$label = 'Clean';
		if ( $score >= 81 ) {
			$label = 'Critical';
		} elseif ( $score >= 61 ) {
			$label = 'High Risk';
		} elseif ( $score >= 41 ) {
			$label = 'Suspicious';
		} elseif ( $score >= 21 ) {
			$label = 'Low Risk';
		}

		return array(
			'score'   => $score,
			'signals' => array_values( array_unique( $signals ) ),
			'label'   => $label,
		);
	}

	/**
	 * Whether score warrants a malware finding.
	 */
	public static function is_actionable( $score_row ) {
		$score   = isset( $score_row['score'] ) ? (int) $score_row['score'] : 0;
		$signals = isset( $score_row['signals'] ) ? (array) $score_row['signals'] : array();
		if ( $score >= 70 && count( $signals ) >= 2 ) {
			return true;
		}
		if ( in_array( 'name_ioc', $signals, true ) && $score >= 55 ) {
			return true;
		}
		return false;
	}
}
