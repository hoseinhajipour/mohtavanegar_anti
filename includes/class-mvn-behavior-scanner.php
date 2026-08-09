<?php
/**
 * Bounded token-based PHP behavior analysis. Payloads are never evaluated.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Behavior_Scanner {

	const MAX_BYTES = 2097152;

	/**
	 * Analyze PHP source and return one evidence-rich finding when warranted.
	 *
	 * @param string $rel     Relative path.
	 * @param string $content PHP source.
	 * @return array|null
	 */
	public static function analyze( $rel, $content ) {
		if ( ! is_string( $content ) || '' === $content ) {
			return null;
		}
		$content = substr( $content, 0, self::MAX_BYTES );
		$tokens  = @token_get_all( $content );
		if ( ! is_array( $tokens ) ) {
			return null;
		}

		$ids = array();
		foreach ( $tokens as $token ) {
			if ( is_array( $token ) && T_STRING === $token[0] ) {
				$ids[] = strtolower( $token[1] );
			}
		}
		$joined   = ' ' . implode( ' ', $ids ) . ' ';
		$evidence = array();
		$score    = 20;

		$input = preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/', $content );
		$exec  = preg_match( '/\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i', $content );
		if ( $input ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'user_input' );
			$score += 12;
		}
		if ( $exec ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'code_or_command_execution' );
			$score += 24;
		}
		if ( $input && $exec ) {
			$score += 30;
		}
		if ( preg_match( '/\$\w+\s*\(\s*(?:\$_|\$\w+)/', $content ) || preg_match( '/call_user_func(?:_array)?\s*\(/i', $content ) ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'dynamic_call' );
			$score += 15;
		}
		if ( preg_match( '/(?:base64_decode|gzinflate|gzdecode|str_rot13|rawurldecode)\s*\([^;]{0,500}(?:base64_decode|gzinflate|eval|assert)/is', $content ) ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'decoder_chain' );
			$score += 20;
		}
		if ( preg_match( '/\b(?:file_put_contents|fwrite|copy|rename|unlink|chmod)\s*\(/i', $content ) ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'filesystem_mutation' );
			$score += 8;
		}
		if ( preg_match( '/(?:all_plugins|show_advanced_plugins|pre_option_active_plugins|wp_insert_user|wp_create_user|administrator|auto_prepend_file|mu-plugins|db\.php)/i', $content ) ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'hiding_or_persistence' );
			$score += 18;
		}
		if ( preg_match( '/\b(?:curl_exec|wp_remote_get|wp_remote_post|fsockopen)\s*\(/i', $content ) && $exec ) {
			$evidence[] = array( 'engine' => 'tokens', 'signal' => 'network_to_execution' );
			$score += 12;
		}
		if ( count( $evidence ) < 2 || $score < 65 ) {
			return null;
		}
		$score = min( 99, $score );
		return array(
			'rel'        => $rel,
			'sig'        => 'behavior_chain',
			'label'      => 'زنجیره رفتاری مشکوک PHP',
			'severity'   => $score >= 95 ? 'critical' : 'warning',
			'detail'     => implode(
				', ',
				array_map(
					static function ( $item ) {
						return $item['signal'];
					},
					$evidence
				)
			),
			'action'     => $score >= 95 ? 'quarantine' : 'manual_review',
			'confidence' => $score,
			'evidence'   => $evidence,
			'source'     => 'behavior',
		);
	}
}
