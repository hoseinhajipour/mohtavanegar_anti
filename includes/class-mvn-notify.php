<?php
/**
 * Critical incident email and privacy-preserving HMAC webhook notifications.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Notify {

	const OPTION = 'mvn_notify_settings';

	public static function settings() {
		return wp_parse_args(
			get_option( self::OPTION, array() ),
			array( 'email' => get_option( 'admin_email' ), 'webhook_url' => '', 'webhook_secret' => '' )
		);
	}

	public static function critical( $incident, $event = 'critical_opened' ) {
		$settings = self::settings();
		$finding  = isset( $incident['finding'] ) ? $incident['finding'] : $incident;
		$payload  = array(
			'event' => $event,
			'incident_id' => isset( $incident['id'] ) ? $incident['id'] : ( isset( $finding['id'] ) ? $finding['id'] : '' ),
			'severity' => isset( $finding['severity'] ) ? $finding['severity'] : '',
			'signature' => isset( $finding['sig'] ) ? $finding['sig'] : '',
			'path' => isset( $finding['rel'] ) ? $finding['rel'] : '',
			'time' => gmdate( 'c' ),
			'site' => wp_parse_url( home_url(), PHP_URL_HOST ),
		);
		if ( ! empty( $settings['email'] ) && is_email( $settings['email'] ) ) {
			wp_mail( $settings['email'], '[MVN] رخداد امنیتی بحرانی', wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE ) );
		}
		if ( empty( $settings['webhook_url'] ) || empty( $settings['webhook_secret'] ) ) {
			return;
		}
		$host  = wp_parse_url( $settings['webhook_url'], PHP_URL_HOST );
		$valid = MVN_URL_Trust::validate( $settings['webhook_url'], array( $host ) );
		if ( is_wp_error( $valid ) ) {
			MVN_Audit_Log::record( 'webhook_blocked', '', '', 'error', array( 'host' => $host ) );
			return;
		}
		$body = wp_json_encode( $payload );
		wp_safe_remote_post(
			$settings['webhook_url'],
			array(
				'timeout' => 10, 'redirection' => 0, 'body' => $body,
				'headers' => array(
					'Content-Type' => 'application/json',
					'X-MVN-Signature' => 'sha256=' . hash_hmac( 'sha256', $body, $settings['webhook_secret'] ),
				),
			)
		);
	}
}
