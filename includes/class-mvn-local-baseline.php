<?php
/**
 * Opt-in SHA-256 baseline for premium/custom plugins and themes.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Local_Baseline {

	const OPTION = 'mvn_local_baseline';

	public static function create( $roots ) {
		$files = array();
		foreach ( (array) $roots as $root ) {
			$root = trim( str_replace( '\\', '/', (string) $root ), '/' );
			if ( ! preg_match( '#^wp-content/(?:plugins|themes)/[^/]+$#', $root ) || mvn_is_self_plugin_path( $root . '/x.php' ) ) {
				continue;
			}
			$abs = mvn_abs_path( $root );
			foreach ( $abs && is_dir( $abs ) ? mvn_list_files( $abs, 50000 ) : array() as $rel ) {
				$file = mvn_abs_path( $rel );
				if ( $file && is_file( $file ) ) {
					$files[ $rel ] = hash_file( 'sha256', $file );
				}
			}
		}
		$baseline = array( 'created_at' => gmdate( 'c' ), 'files' => $files );
		update_option( self::OPTION, $baseline, false );
		return $baseline;
	}

	public static function audit( &$state ) {
		$baseline = get_option( self::OPTION, array() );
		if ( empty( $baseline['files'] ) || ! is_array( $baseline['files'] ) ) {
			return;
		}
		foreach ( $baseline['files'] as $rel => $expected ) {
			$abs    = mvn_abs_path( $rel );
			$actual = $abs && is_file( $abs ) ? hash_file( 'sha256', $abs ) : '';
			if ( is_string( $actual ) && hash_equals( (string) $expected, $actual ) ) {
				continue;
			}
			MVN_Scanner::add_finding(
				$state,
				array(
					'rel' => $rel, 'sig' => 'local_baseline_changed', 'label' => 'تغییر نسبت به baseline محلی',
					'severity' => 'warning', 'detail' => '' === $actual ? 'فایل حذف شده است.' : 'SHA-256 فایل تغییر کرده است.',
					'action' => 'manual_review', 'confidence' => 70, 'source' => 'baseline',
					'evidence' => array( array( 'engine' => 'local-baseline', 'signal' => 'hash_changed' ) ),
				),
				'',
				$actual
			);
		}
	}
}
