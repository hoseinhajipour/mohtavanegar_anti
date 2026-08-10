<?php
/**
 * Security Gateway — rule registry + gateway/htaccess generators.
 *
 * The public_html/index.php gateway must stay tiny and must not depend on
 * this class at runtime (WordPress may not be loaded yet). This class
 * generates that file and an optional core-side rules stub.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Security_Gateway {

	/**
	 * @return MVN_Security_Rule[]
	 */
	public static function default_rules() {
		$rules = array(
			new MVN_Security_Rule_Path_Traversal(),
			new MVN_Security_Rule_Sensitive_Probe(),
		);
		/**
		 * Filter gateway rules (admin-side registry / future runtime rules file).
		 *
		 * @param MVN_Security_Rule[] $rules Rules.
		 */
		return apply_filters( 'mvn_security_gateway_rules', $rules );
	}

	/**
	 * Build lightweight public gateway PHP for a relocated core path.
	 *
	 * @param string $core_path Absolute WordPress core path (outside public root).
	 * @return string PHP source.
	 */
	public static function generate_gateway_php( $core_path ) {
		$core_path = mvn_normalize_path( $core_path );
		$export    = var_export( $core_path, true );
		return <<<PHP
<?php
/**
 * Mohtavanegar Security Gateway
 *
 * Public web-root bootstrap. Loads WordPress from a path outside the
 * document root. Do not place secrets here. Managed by Mohtavanegar Antivirus.
 */
if ( defined( 'MVN_SECURITY_GATEWAY' ) ) {
	return;
}
define( 'MVN_SECURITY_GATEWAY', true );

\$mvn_wp_core = {$export};

if ( ! is_string( \$mvn_wp_core ) || '' === \$mvn_wp_core || ! is_file( \$mvn_wp_core . '/wp-blog-header.php' ) ) {
	header( 'HTTP/1.1 503 Service Unavailable' );
	header( 'Content-Type: text/plain; charset=UTF-8' );
	echo 'Security gateway misconfigured.';
	exit;
}

\$mvn_uri = isset( \$_SERVER['REQUEST_URI'] ) ? (string) \$_SERVER['REQUEST_URI'] : '/';
if ( false !== strpos( \$mvn_uri, "\\0" ) || preg_match( '#(^|/)\\.\\.(/|\$)#', rawurldecode( \$mvn_uri ) ) ) {
	header( 'HTTP/1.0 400 Bad Request' );
	exit;
}

// Optional extensible rules (lives with core, outside public root).
\$mvn_rules = \$mvn_wp_core . '/mvn-gateway-rules.php';
if ( is_file( \$mvn_rules ) ) {
	require \$mvn_rules;
}

define( 'WP_USE_THEMES', true );
require \$mvn_wp_core . '/wp-blog-header.php';

PHP;
	}

	/**
	 * Optional rules file written beside relocated core (not web-accessible).
	 *
	 * @return string PHP source.
	 */
	public static function generate_rules_php() {
		return <<<'PHP'
<?php
/**
 * Mohtavanegar gateway rules (optional).
 *
 * Loaded by public_html/index.php before WordPress boots.
 * Keep rules conservative — Stability > Security > Complexity.
 *
 * Future hooks may add rate limiting, UA filters, XML-RPC guards, etc.
 * Do not log secrets here.
 */
if ( ! defined( 'MVN_SECURITY_GATEWAY' ) ) {
	return;
}

$mvn_gw_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
$mvn_gw_path = parse_url( $mvn_gw_uri, PHP_URL_PATH );
$mvn_gw_path = is_string( $mvn_gw_path ) ? strtolower( $mvn_gw_path ) : '';

// Sensitive file probes (defense in depth; .htaccess should already deny these).
if ( $mvn_gw_path && preg_match( '#/(?:\.env|\.git(?:/|$)|composer\.(?:json|lock)|wp-config\.php(?:\.|$)|[^/]+\.(?:sql|bak|old|log|tar|gz|zip|dist))$#i', $mvn_gw_path ) ) {
	header( 'HTTP/1.0 404 Not Found' );
	exit;
}

PHP;
	}

	/**
	 * Public .htaccess for gateway mode (permalinks + sensitive-file denial).
	 *
	 * Symlinks are required for wp-admin / wp-includes / wp-content exposure.
	 * Parent directories are never aliased.
	 *
	 * @return string
	 */
	public static function generate_htaccess() {
		return <<<'HTACCESS'
# BEGIN MVN Security Gateway
# Managed by Mohtavanegar Antivirus — Security Architecture
Options -Indexes
<IfModule mod_rewrite.c>
	Options +FollowSymLinks
</IfModule>

# Deny dotfiles and common secrets by name
<FilesMatch "(?i)^(\.env|\.htpasswd|\.user\.ini|wp-config\.php|composer\.json|composer\.lock|package\.json|package-lock\.json)$">
	<IfModule mod_authz_core.c>
		Require all denied
	</IfModule>
	<IfModule !mod_authz_core.c>
		Order allow,deny
		Deny from all
	</IfModule>
</FilesMatch>

# Deny backup / dump / archive extensions at the web root
<FilesMatch "(?i)\.(env|sql|bak|old|orig|save|swp|log|tar|gz|tgz|zip|rar|7z|dist|inc)$">
	<IfModule mod_authz_core.c>
		Require all denied
	</IfModule>
	<IfModule !mod_authz_core.c>
		Order allow,deny
		Deny from all
	</IfModule>
</FilesMatch>

# Hide VCS and env paths
RedirectMatch 404 (?i)/\.(?:git|svn|hg|env)(?:/|$)

# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
# END MVN Security Gateway

HTACCESS;
	}

	/**
	 * Uploads deny-PHP htaccess body.
	 *
	 * @return string
	 */
	public static function uploads_htaccess() {
		$bundled = MVN_PLUGIN_DIR . 'sources/uploads.htaccess';
		if ( is_file( $bundled ) ) {
			$raw = (string) @file_get_contents( $bundled );
			if ( '' !== trim( $raw ) ) {
				return $raw;
			}
		}
		return "# BEGIN Mohtavanegar Uploads Deny PHP\n<IfModule mod_authz_core.c>\n\t<FilesMatch \"\\.(?i:php|phtml|php3|php4|php5|php7|php8|phar|cgi|pl|shtml)$\">\n\t\tRequire all denied\n\t</FilesMatch>\n</IfModule>\n<IfModule !mod_authz_core.c>\n\t<FilesMatch \"\\.(?i:php|phtml|php3|php4|php5|php7|php8|phar|cgi|pl|shtml)$\">\n\t\tOrder Allow,Deny\n\t\tDeny from all\n\t</FilesMatch>\n</IfModule>\n# END Mohtavanegar Uploads Deny PHP\n";
	}
}
