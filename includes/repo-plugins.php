<?php
/**
 * Catalog of free WordPress.org plugins that can be reinstalled from the repository.
 *
 * slug  = WordPress.org plugin slug (used in download URL)
 * name  = display name (Persian or English)
 * folder = expected directory under wp-content/plugins/ (usually same as slug)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function mvn_repo_plugins() {
	$list = array(
		array(
			'slug'   => 'elementor',
			'name'   => 'Elementor',
			'folder' => 'elementor',
		),
		array(
			'slug'   => 'persian-elementor',
			'name'   => 'المنتور فارسی',
			'folder' => 'persian-elementor',
		),
		array(
			'slug'   => 'woocommerce',
			'name'   => 'WooCommerce',
			'folder' => 'woocommerce',
		),
		array(
			'slug'   => 'persian-woocommerce',
			'name'   => 'ووکامرس فارسی',
			'folder' => 'persian-woocommerce',
		),
		array(
			'slug'   => 'classic-editor',
			'name'   => 'ویرایشگر کلاسیک',
			'folder' => 'classic-editor',
		),
		array(
			'slug'   => 'litespeed-cache',
			'name'   => 'LiteSpeed Cache',
			'folder' => 'litespeed-cache',
		),
		array(
			'slug'   => 'contact-form-7',
			'name'   => 'Contact Form 7',
			'folder' => 'contact-form-7',
		),
		array(
			'slug'   => 'wordpress-seo',
			'name'   => 'Yoast SEO',
			'folder' => 'wordpress-seo',
		),
		array(
			'slug'   => 'wordfence',
			'name'   => 'Wordfence Security',
			'folder' => 'wordfence',
		),
		array(
			'slug'   => 'updraftplus',
			'name'   => 'UpdraftPlus',
			'folder' => 'updraftplus',
		),
		array(
			'slug'   => 'wpforms-lite',
			'name'   => 'WPForms Lite',
			'folder' => 'wpforms-lite',
		),
		array(
			'slug'   => 'akismet',
			'name'   => 'Akismet',
			'folder' => 'akismet',
		),
		array(
			'slug'   => 'really-simple-ssl',
			'name'   => 'Really Simple SSL',
			'folder' => 'really-simple-ssl',
		),
	);

	return apply_filters( 'mvn_repo_plugins', $list );
}

/**
 * Find a catalog entry by slug.
 */
function mvn_repo_plugin_by_slug( $slug ) {
	$slug = sanitize_key( $slug );
	foreach ( mvn_repo_plugins() as $plugin ) {
		if ( $plugin['slug'] === $slug ) {
			return $plugin;
		}
	}
	return null;
}
