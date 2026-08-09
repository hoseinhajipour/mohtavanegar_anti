<?php
/**
 * Shared anti-SSRF URL policy for WordPress.org and signed intelligence hosts.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_URL_Trust {

	public static function allowed_hosts() {
		$hosts = array( 'api.wordpress.org', 'downloads.wordpress.org' );
		if ( defined( 'MVN_SIGNATURE_PACK_HOST' ) && MVN_SIGNATURE_PACK_HOST ) {
			$hosts[] = strtolower( trim( MVN_SIGNATURE_PACK_HOST ) );
		}
		return array_values( array_unique( apply_filters( 'mvn_trusted_download_hosts', $hosts ) ) );
	}

	public static function validate( $url, $allowed_hosts = null ) {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || 'https' !== strtolower( isset( $parts['scheme'] ) ? $parts['scheme'] : '' ) || empty( $parts['host'] ) ) {
			return new WP_Error( 'untrusted_url', 'فقط HTTPS با host مجاز پذیرفته می‌شود.' );
		}
		$host  = strtolower( rtrim( $parts['host'], '.' ) );
		$allow = null === $allowed_hosts ? self::allowed_hosts() : (array) $allowed_hosts;
		if ( ! in_array( $host, array_map( 'strtolower', $allow ), true ) ) {
			return new WP_Error( 'untrusted_host', 'Host دانلود در allowlist نیست: ' . $host );
		}
		if ( filter_var( $host, FILTER_VALIDATE_IP ) && self::is_private_ip( $host ) ) {
			return new WP_Error( 'private_ip', 'آدرس private/loopback/link-local مجاز نیست.' );
		}
		$ips = array();
		if ( function_exists( 'dns_get_record' ) ) {
			foreach ( (array) @dns_get_record( $host, DNS_A | DNS_AAAA ) as $row ) {
				if ( ! empty( $row['ip'] ) ) {
					$ips[] = $row['ip'];
				}
				if ( ! empty( $row['ipv6'] ) ) {
					$ips[] = $row['ipv6'];
				}
			}
		} else {
			$resolved = @gethostbyname( $host );
			if ( $resolved && $resolved !== $host ) {
				$ips[] = $resolved;
			}
		}
		foreach ( $ips as $ip ) {
			if ( self::is_private_ip( $ip ) ) {
				return new WP_Error( 'dns_private_ip', 'DNS host به IP خصوصی/محلی resolve شد.' );
			}
		}
		return true;
	}

	private static function is_private_ip( $ip ) {
		return false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	public static function get( $url, $args = array(), $allowed_hosts = null ) {
		$valid = self::validate( $url, $allowed_hosts );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		$args['redirection'] = 0;
		$args['reject_unsafe_urls'] = true;
		return wp_safe_remote_get( $url, $args );
	}
}
