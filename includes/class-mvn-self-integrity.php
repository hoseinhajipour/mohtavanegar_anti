<?php
/**
 * Plugin self-integrity against bundled or signed-pack SHA-256 manifest.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Self_Integrity {

	public static function manifest() {
		$pack = MVN_Signature_Pack::load();
		if ( 'local' === $pack['source'] && ! empty( $pack['plugin_manifest']['files'] ) ) {
			return array( 'source' => 'signed-remote', 'files' => $pack['plugin_manifest']['files'] );
		}
		$file = MVN_PLUGIN_DIR . 'sources/integrity-manifest.json';
		$data = is_file( $file ) ? json_decode( (string) @file_get_contents( $file ), true ) : null;
		return is_array( $data ) ? array( 'source' => 'bundled', 'files' => isset( $data['files'] ) ? $data['files'] : array() ) : array( 'source' => 'none', 'files' => array() );
	}

	public static function verify() {
		$manifest = self::manifest();
		$changed  = array();
		$missing  = array();
		foreach ( $manifest['files'] as $rel => $expected ) {
			if ( false !== strpos( $rel, '..' ) || ! preg_match( '/\.(?:php|js|css|json)$/i', $rel ) ) {
				continue;
			}
			$file = MVN_PLUGIN_DIR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );
			if ( ! is_file( $file ) ) {
				$missing[] = $rel;
			} elseif ( ! hash_equals( strtolower( (string) $expected ), hash_file( 'sha256', $file ) ) ) {
				$changed[] = $rel;
			}
		}
		return array(
			'ok' => ! empty( $manifest['files'] ) && empty( $changed ) && empty( $missing ),
			'source' => $manifest['source'],
			'checked' => count( $manifest['files']),
			'changed' => $changed,
			'missing' => $missing,
			'checked_at' => gmdate( 'c' ),
		);
	}
}
