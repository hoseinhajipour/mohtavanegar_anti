<?php
/**
 * Plugin Name: Benign MU Fixture
 */
add_action(
	'plugins_loaded',
	static function () {
		// Legitimate bootstrap: no input, decoder, dynamic execution, or persistence write.
	}
);
