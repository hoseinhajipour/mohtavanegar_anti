<?php
/**
 * Generates bounded zip-slip and high-ratio archives for local tests.
 */

if ( ! class_exists( 'ZipArchive' ) ) {
	exit( 0 );
}
$zip = new ZipArchive();
$zip->open( __DIR__ . '/archive-bomb-slip.zip', ZipArchive::CREATE | ZipArchive::OVERWRITE );
$zip->addFromString( '../escape.php.txt', 'zip-slip fixture' );
$zip->addFromString( 'high-ratio.txt', str_repeat( 'A', 2 * 1024 * 1024 ) );
$zip->close();
