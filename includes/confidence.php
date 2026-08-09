<?php
/**
 * Confidence scores for scan findings (0–100).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base confidence per signature id.
 */
function mvn_signature_confidence_map() {
	$map = array(
		'eval_decoder'              => 94,
		'eval_request'              => 96,
		'nested_decoders'           => 90,
		'preg_replace_e'            => 93,
		'create_function'           => 42,
		'shell_exec_request'        => 95,
		'hex_include'               => 91,
		'long_base64_blob'          => 48,
		'hex_string_chain'          => 40,
		'chr_chain'                 => 38,
		'globals_obfuscation'       => 45,
		'variable_variables_eval'   => 72,
		'webshell_markers'          => 88,
		'php_upload_in_uploads'     => 97,
		'prepend_wrapper'           => 86,
		'error_reporting_eval_combo'=> 89,
		'set_time_limit_shell'      => 84,
		'js_unescape'               => 90,
		'js_fromcharcode'           => 55,
		'js_atob_eval'              => 92,
		'hidden_iframe'             => 50,
		'suspicious_script_src'     => 62,
		'ht_auto_prepend'           => 93,
		'ht_sethandler_php'         => 91,
		'ht_addhandler_ext'         => 90,
		'ht_rewrite_payload'        => 58,
		'rogue_htaccess'            => 87,
		'php_in_uploads'            => 97,
		'polyglot_php_in_media'     => 98,
		'known_malware_hash'        => 99,
		'unexpected_dropin'         => 96,
		'wpcontent_hex_php'         => 99,
		'wpcontent_hex_zip'         => 97,
		'user_ini_prepend'          => 99,
		'user_ini_wpcontent'        => 90,
		'suspicious_db_dropin'      => 95,
		'known_malware_plugin'      => 99,
		'hidden_plugin_filter'      => 97,
		'orphan_stealth_plugin'     => 94,
		'xdav_tracker_markers'      => 99,
		'zonal_runner_tap_markers'  => 99,
		'malware_persistence_dropper'=> 98,
		'shutdown_js_inject'        => 93,
		'hide_plugin_user_hooks'    => 95,
		'stealth_admin_recreate'    => 96,
		'db_ghost_admin'            => 98,
		'db_malware_tracker_option' => 97,
		'db_malware_tracker_usermeta' => 96,
		'repo_checksum_modified'    => 97,
		'repo_checksum_missing'     => 95,
		'repo_checksum_extra'       => 88,
		'db_rogue_option_name'      => 92,
		'db_hidden_admin'           => 95,
		'db_admin_capability'       => 94,
		'db_spam_injection'         => 68,
		'db_serialized_shell'       => 90,
		'db_cron_injection'         => 96,
		'as_payload_malware'        => 97,
		'as_suspicious_hook'        => 82,
		'as_suspicious_group'       => 70,
		'as_unknown_hook_blob'      => 90,
		'core_checksum_modified'    => 98,
		'core_checksum_missing'     => 97,
		'core_checksum_extra'       => 93,
		'core_checksum_unavailable' => 40,
	);

	return apply_filters( 'mvn_signature_confidence_map', $map );
}

/**
 * Compute final confidence for a finding.
 */
function mvn_compute_confidence( $sig_id, $severity, $rel, $content = '' ) {
	$map  = mvn_signature_confidence_map();
	$base = isset( $map[ $sig_id ] ) ? (int) $map[ $sig_id ] : ( 'critical' === $severity ? 78 : ( 'warning' === $severity ? 52 : 35 ) );

	$rel = str_replace( '\\', '/', (string) $rel );

	if ( 0 === strpos( $rel, 'wp-content/uploads/' ) ) {
		$base = min( 99, $base + 12 );
	}
	if ( 0 === strpos( $rel, 'db:' ) ) {
		$base = min( 99, $base + 6 );
		if ( false !== strpos( $rel, ':options:' ) ) {
			$base = min( 99, $base + 4 );
		}
	}
	if ( 0 === strpos( $rel, 'as:' ) ) {
		$base = min( 99, $base + 8 );
	}
	if ( 0 === strpos( $rel, 'wp-content/plugins/' ) && in_array( $sig_id, array( 'chr_chain', 'long_base64_blob', 'hex_string_chain', 'create_function', 'hidden_iframe' ), true ) ) {
		$base = max( 15, $base - 18 );
	}
	if ( preg_match( '#/(vendor|node_modules)/#', $rel ) ) {
		$base = max( 10, $base - 25 );
	}
	if ( in_array( $sig_id, array( 'eval_decoder', 'eval_request', 'shell_exec_request', 'webshell_markers' ), true ) ) {
		$base = min( 99, $base + 4 );
	}

	$base = (int) apply_filters( 'mvn_compute_confidence', $base, $sig_id, $severity, $rel, $content );
	return max( 5, min( 99, $base ) );
}

/**
 * Human label for confidence tier.
 */
function mvn_confidence_label( $score ) {
	$score = (int) $score;
	if ( $score >= 85 ) {
		return 'بسیار بالا';
	}
	if ( $score >= 65 ) {
		return 'بالا';
	}
	if ( $score >= 45 ) {
		return 'متوسط';
	}
	return 'پایین';
}

/**
 * CSS class suffix for confidence tier.
 */
function mvn_confidence_class( $score ) {
	$score = (int) $score;
	if ( $score >= 85 ) {
		return 'high';
	}
	if ( $score >= 65 ) {
		return 'mid';
	}
	if ( $score >= 45 ) {
		return 'low';
	}
	return 'very-low';
}
