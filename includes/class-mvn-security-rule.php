<?php
/**
 * Extensible security-gateway rule contract.
 *
 * Rules run from the lightweight public gateway (or optional core rules file).
 * Default rules must remain non-aggressive so legitimate WordPress traffic works.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class MVN_Security_Rule {

	/**
	 * Machine id for the rule.
	 *
	 * @return string
	 */
	abstract public function id();

	/**
	 * Human label.
	 *
	 * @return string
	 */
	abstract public function label();

	/**
	 * Whether the rule is enabled by default.
	 *
	 * @return bool
	 */
	public function enabled_by_default() {
		return true;
	}

	/**
	 * Evaluate the current request.
	 *
	 * Return true to allow, false to block. Implementations must avoid
	 * breaking admin, login, REST, AJAX, cron, or static assets unless
	 * the request is clearly malicious.
	 *
	 * @param array $context Request context (uri, method, ip, ua).
	 * @return bool
	 */
	abstract public function allow( array $context );
}

/**
 * Block null bytes and obvious path-traversal in REQUEST_URI.
 */
class MVN_Security_Rule_Path_Traversal extends MVN_Security_Rule {

	public function id() {
		return 'path_traversal';
	}

	public function label() {
		return 'Path traversal / null-byte guard';
	}

	public function allow( array $context ) {
		$uri = isset( $context['uri'] ) ? (string) $context['uri'] : '';
		if ( false !== strpos( $uri, "\0" ) ) {
			return false;
		}
		$decoded = rawurldecode( $uri );
		if ( preg_match( '#(^|/)\.\.(/|$)#', $decoded ) ) {
			return false;
		}
		return true;
	}
}

/**
 * Reject clearly dangerous file-extension probes outside uploads media types.
 * Intentionally narrow — does not block normal WP PHP endpoints.
 */
class MVN_Security_Rule_Sensitive_Probe extends MVN_Security_Rule {

	public function id() {
		return 'sensitive_probe';
	}

	public function label() {
		return 'Sensitive file probe guard';
	}

	public function allow( array $context ) {
		$uri = isset( $context['uri'] ) ? strtolower( (string) $context['uri'] ) : '';
		$path = parse_url( $uri, PHP_URL_PATH );
		$path = is_string( $path ) ? $path : $uri;
		if ( preg_match( '#/(?:\.env|\.git(?:/|$)|composer\.(?:json|lock)|wp-config\.php(?:\.|$)|[^/]+\.(?:sql|bak|old|log|tar|gz|zip|dist))$#i', $path ) ) {
			return false;
		}
		return true;
	}
}
