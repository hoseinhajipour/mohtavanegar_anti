<?php
/**
 * Persistence phase — MU/drop-ins/cron/options correlation for reinfection sources.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Persistence_Scanner {

	const CHUNK = 25;

	/**
	 * Begin persistence phase after AS (or when AS skipped).
	 *
	 * @param array $state Scan state by ref.
	 */
	public static function begin_phase( &$state ) {
		$queue = self::build_queue();
		$state['phase']               = 'persistence';
		$state['persist_queue']       = $queue;
		$state['persist_cursor']      = 0;
		$state['persist_total']       = count( $queue );
		$state['persist_processed']   = 0;
		$state['total']               = max( 1, count( $queue ) );
		$state['processed']           = 0;
		$state['cursor']              = 0;
		if ( ! isset( $state['stats']['persistence'] ) ) {
			$state['stats']['persistence'] = 0;
		}
		self::snapshot_cron_and_options();
		mvn_log( 'Persistence phase started: items=' . count( $queue ) );
	}

	/**
	 * @return string[] Relative paths / tokens to inspect.
	 */
	private static function build_queue() {
		$queue = array();

		// MU plugins.
		$mu = trailingslashit( WP_CONTENT_DIR ) . 'mu-plugins';
		if ( is_dir( $mu ) ) {
			$items = @scandir( $mu );
			if ( is_array( $items ) ) {
				foreach ( $items as $item ) {
					if ( '.' === $item || '..' === $item ) {
						continue;
					}
					$path = $mu . '/' . $item;
					if ( is_file( $path ) && preg_match( '/\.(?:php|phtml|php\d)$/i', $item ) ) {
						$queue[] = 'wp-content/mu-plugins/' . $item;
					} elseif ( is_dir( $path ) ) {
						$sub = @scandir( $path );
						if ( is_array( $sub ) ) {
							foreach ( $sub as $s ) {
								if ( preg_match( '/\.php$/i', $s ) && is_file( $path . '/' . $s ) ) {
									$queue[] = 'wp-content/mu-plugins/' . $item . '/' . $s;
								}
							}
						}
					}
				}
			}
		}

		// Known drop-ins + wp-content root IoCs.
		foreach ( array( 'db.php', 'advanced-cache.php', 'object-cache.php', 'sunrise.php', 'maintenance.php' ) as $drop ) {
			$rel = 'wp-content/' . $drop;
			if ( is_file( mvn_abs_path( $rel ) ) ) {
				$queue[] = $rel;
			}
		}
		if ( class_exists( 'MVN_Ghost_Plugins' ) ) {
			foreach ( MVN_Ghost_Plugins::discover_wpcontent_root_iocs() as $rel ) {
				$queue[] = $rel;
			}
		}

		// Active theme critical files.
		$theme = get_stylesheet_directory();
		if ( $theme && is_dir( $theme ) ) {
			foreach ( array( 'functions.php', 'header.php', 'footer.php', 'index.php' ) as $tf ) {
				$abs = trailingslashit( $theme ) . $tf;
				if ( is_file( $abs ) ) {
					$queue[] = mvn_rel_path( $abs );
				}
			}
		}

		// Synthetic tokens for cron / options pass.
		$queue[] = '__cron__';
		$queue[] = '__options__';
		$queue[] = '__watched__';

		return array_values( array_unique( $queue ) );
	}

	public static function tick( &$state ) {
		$queue  = isset( $state['persist_queue'] ) ? $state['persist_queue'] : array();
		$cursor = isset( $state['persist_cursor'] ) ? (int) $state['persist_cursor'] : 0;
		$total  = count( $queue );
		$end    = min( $cursor + self::CHUNK, $total );

		for ( $i = $cursor; $i < $end; $i++ ) {
			$item = $queue[ $i ];
			if ( '__cron__' === $item ) {
				self::scan_cron( $state );
			} elseif ( '__options__' === $item ) {
				self::scan_tracker_options( $state );
			} elseif ( '__watched__' === $item ) {
				self::scan_watched_reinfection( $state );
			} else {
				self::scan_file( $item, $state );
			}
		}

		$state['persist_cursor']    = $end;
		$state['persist_processed'] = $end;
		$state['processed']         = $end;
		$state['cursor']            = $end;
		$state['total']             = max( 1, $total );
	}

	public static function is_done( $state ) {
		$total  = isset( $state['persist_total'] ) ? (int) $state['persist_total'] : 0;
		$cursor = isset( $state['persist_cursor'] ) ? (int) $state['persist_cursor'] : 0;
		return $cursor >= $total;
	}

	private static function scan_file( $rel, &$state ) {
		$abs = mvn_abs_path( $rel );
		if ( ! $abs || ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return;
		}
		if ( class_exists( 'MVN_Ghost_Plugins' ) && MVN_Ghost_Plugins::is_mvn_safe_dropin( $abs ) ) {
			return;
		}
		$content = (string) @file_get_contents( $abs );
		if ( '' === $content ) {
			return;
		}
		MVN_File_Hash_Store::touch( $rel );
		$score = MVN_XDav_Signatures::score( $rel, substr( $content, 0, 512000 ) );
		MVN_File_Hash_Store::touch(
			$rel,
			array(
				'risk_score' => $score['score'],
				'status'     => MVN_XDav_Signatures::is_actionable( $score ) ? 'suspicious' : 'seen',
			)
		);

		if ( ! MVN_XDav_Signatures::is_actionable( $score ) ) {
			// Persistence writers without full XDav name still matter in MU.
			if ( 0 === strpos( $rel, 'wp-content/mu-plugins/' )
				&& in_array( 'persistence_write', $score['signals'], true )
				&& $score['score'] >= 50 ) {
				// continue to flag below
			} else {
				return;
			}
		}

		$correlated = self::correlate_for_path( $rel, (int) @filemtime( $abs ) );
		$finding    = array(
			'rel'          => $rel,
			'sig'          => 'persistence_source',
			'label'        => 'منبع Persistence / احتمال reinfection',
			'severity'     => $score['score'] >= 80 ? 'critical' : 'warning',
			'detail'       => 'امتیاز ' . $score['score'] . ' (' . $score['label'] . ') — سیگنال: ' . implode( ', ', $score['signals'] ),
			'action'       => 'quarantine',
			'confidence'   => min( 99, max( 60, $score['score'] ) ),
			'source'       => 'persistence',
			'risk_score'   => $score['score'],
			'persistence'  => $correlated,
			'snippet'      => mb_substr( preg_replace( '/\s+/', ' ', $content ), 0, 180 ),
		);
		if ( MVN_Scanner::add_finding( $state, $finding, $content, hash( 'sha256', $content ) ) ) {
			$state['stats']['persistence']++;
			$state['stats'][ $finding['severity'] ] = isset( $state['stats'][ $finding['severity'] ] ) ? $state['stats'][ $finding['severity'] ] + 1 : 1;
			if ( class_exists( 'MVN_Security_Log' ) ) {
				MVN_Security_Log::write( 'malware_detected', $rel, 'persistence' );
			}
		}
	}

	/**
	 * Correlate nearby file/cron/option changes with a malware path.
	 *
	 * @return array[]
	 */
	public static function correlate_for_path( $rel, $mtime ) {
		$out = array();
		foreach ( MVN_File_Hash_Store::changed_near( $mtime, 600 ) as $row ) {
			if ( isset( $row['path'] ) && $row['path'] === $rel ) {
				continue;
			}
			$out[] = array(
				'type'       => 'file',
				'path'       => isset( $row['path'] ) ? $row['path'] : '',
				'risk_score' => isset( $row['risk_score'] ) ? (int) $row['risk_score'] : 0,
				'modified'   => ! empty( $row['mtime'] ) ? gmdate( 'H:i:s', (int) $row['mtime'] ) : '',
			);
		}
		$cron = _get_cron_array();
		if ( is_array( $cron ) ) {
			foreach ( $cron as $ts => $hooks ) {
				if ( abs( (int) $ts - (int) $mtime ) > 900 ) {
					continue;
				}
				foreach ( (array) $hooks as $hook => $_ ) {
					if ( preg_match( '/(?:xdav|zonal|security.?helper|wp.?compat|malware|backdoor)/i', (string) $hook ) ) {
						$out[] = array(
							'type'       => 'cron',
							'path'       => (string) $hook,
							'risk_score' => 91,
							'modified'   => gmdate( 'H:i:s', (int) $ts ),
						);
					}
				}
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return (int) $b['risk_score'] - (int) $a['risk_score'];
			}
		);
		return array_slice( $out, 0, 12 );
	}

	private static function scan_cron( &$state ) {
		$cron = _get_cron_array();
		if ( ! is_array( $cron ) ) {
			return;
		}
		foreach ( $cron as $ts => $hooks ) {
			foreach ( (array) $hooks as $hook => $entries ) {
				if ( ! preg_match( '/(?:xdav|zonal|security.?helper|wp.?compat|pre_user|sys_maint)/i', (string) $hook ) ) {
					continue;
				}
				$finding = array(
					'rel'        => 'cron:' . $hook,
					'sig'        => 'persistence_cron',
					'label'      => 'کرون مشکوک Persistence',
					'severity'   => 'critical',
					'detail'     => 'hook=' . $hook . ' next=' . gmdate( 'c', (int) $ts ),
					'action'     => 'persist_disable_cron',
					'confidence' => 92,
					'source'     => 'persistence',
					'cron_hook'  => $hook,
					'cron_ts'    => (int) $ts,
				);
				if ( MVN_Scanner::add_finding( $state, $finding, $hook, md5( $hook ) ) ) {
					$state['stats']['persistence']++;
				}
			}
		}
	}

	private static function scan_tracker_options( &$state ) {
		global $wpdb;
		$names = class_exists( 'MVN_Ghost_Plugins' ) ? MVN_Ghost_Plugins::malware_option_names() : array( '_pre_user_id' );
		foreach ( $names as $name ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_id, option_name, option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $name ), ARRAY_A );
			if ( ! $row ) {
				continue;
			}
			$finding = array(
				'rel'        => 'db:options:' . $name . ':option_name',
				'sig'        => 'db_malware_tracker_option',
				'label'      => 'option ردیابی بدافزار',
				'severity'   => 'critical',
				'detail'     => 'Persistence option: ' . $name,
				'action'     => 'persist_delete_option',
				'confidence' => 95,
				'source'     => 'persistence',
				'table'      => 'options',
				'row_id'     => (int) $row['option_id'],
				'column'     => 'option_name',
			);
			if ( MVN_Scanner::add_finding( $state, $finding, $name, md5( $name ) ) ) {
				$state['stats']['persistence']++;
			}
		}
	}

	private static function scan_watched_reinfection( &$state ) {
		$watched = get_option( 'mvn_watched_paths', array() );
		if ( ! is_array( $watched ) ) {
			return;
		}
		foreach ( $watched as $rel => $meta ) {
			$abs = mvn_abs_path( $rel );
			if ( ! $abs || ! is_file( $abs ) ) {
				continue;
			}
			$finding = array(
				'rel'        => $rel,
				'sig'        => 'reinfection_detected',
				'label'      => 'REINFECTION DETECTED',
				'severity'   => 'critical',
				'detail'     => 'فایل پس از قرنطینه دوباره ایجاد شده — Persistence هنوز فعال است.',
				'action'     => 'quarantine',
				'confidence' => 99,
				'source'     => 'persistence',
				'persistence'=> self::correlate_for_path( $rel, (int) @filemtime( $abs ) ),
			);
			if ( MVN_Scanner::add_finding( $state, $finding, (string) @file_get_contents( $abs ), '' ) ) {
				$state['stats']['persistence']++;
				if ( class_exists( 'MVN_Security_Log' ) ) {
					MVN_Security_Log::write( 'reinfection_detected', $rel, 'watched' );
				}
				if ( class_exists( 'MVN_Incidents' ) ) {
					$id = isset( $meta['issue_id'] ) ? $meta['issue_id'] : md5( $rel . '|reinfection_detected' );
					MVN_Incidents::transition( $id, 'open', 'reinfection-monitor', array( 'reinfection' => true ) );
				}
			}
		}
	}

	private static function snapshot_cron_and_options() {
		$cron = _get_cron_array();
		$snap = array(
			'at'        => gmdate( 'c' ),
			'cron_hash' => md5( wp_json_encode( is_array( $cron ) ? array_keys( $cron ) : array() ) ),
		);
		update_option( 'mvn_persistence_snapshots', $snap, false );
	}

	/**
	 * Inventory for Cron Monitor UI.
	 *
	 * @return array[]
	 */
	public static function cron_inventory() {
		$cron = _get_cron_array();
		$out  = array();
		if ( ! is_array( $cron ) ) {
			return $out;
		}
		foreach ( $cron as $ts => $hooks ) {
			foreach ( (array) $hooks as $hook => $entries ) {
				$risk = preg_match( '/(?:xdav|zonal|security.?helper|wp.?compat)/i', (string) $hook ) ? 90 : 10;
				$out[] = array(
					'hook'       => (string) $hook,
					'next_run'   => (int) $ts,
					'next_human' => gmdate( 'Y-m-d H:i:s', (int) $ts ) . ' UTC',
					'count'      => is_array( $entries ) ? count( $entries ) : 0,
					'risk_score' => $risk,
				);
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				if ( $a['risk_score'] !== $b['risk_score'] ) {
					return $b['risk_score'] - $a['risk_score'];
				}
				return $a['next_run'] - $b['next_run'];
			}
		);
		return $out;
	}
}
