<?php
/**
 * Database scanner — options, posts, postmeta, users, usermeta.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_DB_Scanner {

	/**
	 * Initialize DB phase after file scan completes.
	 */
	public static function begin_phase( &$state ) {
		global $wpdb;

		$counts = self::count_rows();
		$total  = array_sum( $counts );

		$state['phase']           = 'db';
		$state['db_phase']        = 'options';
		$state['db_cursor']       = 0;
		$state['db_total']        = $total;
		$state['db_processed']    = 0;
		$state['db_counts']       = $counts;
		$state['file_total']      = isset( $state['total'] ) ? (int) $state['total'] : 0;
		$state['file_processed']  = isset( $state['processed'] ) ? (int) $state['processed'] : 0;
		$state['total']           = $total;
		$state['processed']       = 0;
		$state['cursor']          = 0;
		$state['files']           = array();
		$state['all_files']       = array();

		if ( ! isset( $state['stats']['db'] ) ) {
			$state['stats']['db'] = 0;
		}

		mvn_log( 'DB scan phase started: total rows=' . $total );
	}

	/**
	 * Process one chunk of DB rows.
	 */
	public static function tick( &$state ) {
		$sub   = isset( $state['db_phase'] ) ? $state['db_phase'] : 'options';
		$limit = mvn_db_chunk_size();
		$sigs  = mvn_signatures();

		$done_in_chunk = self::scan_sub_phase( $sub, (int) $state['db_cursor'], $limit, $sigs, $state );
		$state['db_cursor']    += $done_in_chunk;
		$state['db_processed'] += $done_in_chunk;
		$state['processed']     = (int) $state['db_processed'];
		$state['cursor']        = (int) $state['db_cursor'];

		$sub_total = isset( $state['db_counts'][ $sub ] ) ? (int) $state['db_counts'][ $sub ] : 0;
		if ( $state['db_cursor'] >= $sub_total ) {
			$next = self::next_sub_phase( $sub );
			if ( $next ) {
				$state['db_phase']  = $next;
				$state['db_cursor'] = 0;
			}
		}
	}

	public static function is_done( $state ) {
		$sub = isset( $state['db_phase'] ) ? $state['db_phase'] : '';
		if ( 'usermeta' !== $sub ) {
			return false;
		}
		$sub_total = isset( $state['db_counts']['usermeta'] ) ? (int) $state['db_counts']['usermeta'] : 0;
		$cursor    = isset( $state['db_cursor'] ) ? (int) $state['db_cursor'] : 0;
		return $cursor >= $sub_total;
	}

	public static function sub_phase_label( $sub ) {
		$labels = array(
			'options'  => 'options (تنظیمات)',
			'posts'    => 'posts (نوشته‌ها)',
			'postmeta' => 'postmeta (متای نوشته)',
			'users'    => 'users (کاربران)',
			'usermeta' => 'usermeta (متای کاربر)',
		);
		return isset( $labels[ $sub ] ) ? $labels[ $sub ] : $sub;
	}

	private static function next_sub_phase( $current ) {
		$phases = mvn_db_sub_phases();
		$idx    = array_search( $current, $phases, true );
		if ( false === $idx || $idx >= count( $phases ) - 1 ) {
			return '';
		}
		return $phases[ $idx + 1 ];
	}

	private static function count_rows() {
		global $wpdb;

		$options = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->options}
			WHERE option_name NOT LIKE '\_transient\_timeout\_%'
			AND option_name NOT LIKE '\_site\_transient\_timeout\_%'"
		);

		$posts = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status NOT IN ('trash','auto-draft')"
		);

		$postmeta = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->postmeta}" );
		$users    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );
		$usermeta = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta}" );

		return array(
			'options'  => $options,
			'posts'    => $posts,
			'postmeta' => $postmeta,
			'users'    => $users,
			'usermeta' => $usermeta,
		);
	}

	private static function scan_sub_phase( $sub, $cursor, $limit, $sigs, &$state ) {
		switch ( $sub ) {
			case 'options':
				return self::scan_options( $cursor, $limit, $sigs, $state );
			case 'posts':
				return self::scan_posts( $cursor, $limit, $sigs, $state );
			case 'postmeta':
				return self::scan_postmeta( $cursor, $limit, $sigs, $state );
			case 'users':
				return self::scan_users( $cursor, $limit, $sigs, $state );
			case 'usermeta':
				return self::scan_usermeta( $cursor, $limit, $sigs, $state );
		}
		return 0;
	}

	private static function scan_options( $offset, $limit, $sigs, &$state ) {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_id, option_name, option_value FROM {$wpdb->options}
				WHERE option_name NOT LIKE '\_transient\_timeout\_%'
				AND option_name NOT LIKE '\_site\_transient\_timeout\_%'
				ORDER BY option_id ASC
				LIMIT %d OFFSET %d",
				$limit,
				$offset
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			return 0;
		}

		foreach ( $rows as $row ) {
			if ( apply_filters( 'mvn_db_scan_skip_option', false, $row['option_name'], $row['option_value'], $row ) ) {
				continue;
			}
			if ( mvn_db_is_benign_option( $row['option_name'] ) ) {
				continue;
			}
			self::scan_row( 'options', $row, array( 'option_name', 'option_value' ), $sigs, $state );
		}

		return count( $rows );
	}

	private static function scan_posts( $offset, $limit, $sigs, &$state ) {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content, post_excerpt, guid, post_type, post_status
				FROM {$wpdb->posts}
				WHERE post_status NOT IN ('trash','auto-draft')
				ORDER BY ID ASC
				LIMIT %d OFFSET %d",
				$limit,
				$offset
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			return 0;
		}

		foreach ( $rows as $row ) {
			if ( apply_filters( 'mvn_db_scan_skip_post', false, $row ) ) {
				continue;
			}
			if ( 'attachment' === $row['post_type'] ) {
				self::scan_row( 'posts', $row, array( 'post_title', 'guid' ), $sigs, $state );
			} else {
				self::scan_row( 'posts', $row, array( 'post_title', 'post_content', 'post_excerpt', 'guid' ), $sigs, $state );
			}
		}

		return count( $rows );
	}

	private static function scan_postmeta( $offset, $limit, $sigs, &$state ) {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT meta_id, post_id, meta_key, meta_value FROM {$wpdb->postmeta}
				ORDER BY meta_id ASC
				LIMIT %d OFFSET %d",
				$limit,
				$offset
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			return 0;
		}

		foreach ( $rows as $row ) {
			if ( ! empty( $row['meta_key'] ) && mvn_db_is_benign_meta_key( $row['meta_key'] ) ) {
				continue;
			}
			self::scan_row( 'postmeta', $row, array( 'meta_key', 'meta_value' ), $sigs, $state );
		}

		return count( $rows );
	}

	private static function scan_users( $offset, $limit, $sigs, &$state ) {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, user_login, user_email, user_url, display_name FROM {$wpdb->users}
				ORDER BY ID ASC
				LIMIT %d OFFSET %d",
				$limit,
				$offset
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			return 0;
		}

		foreach ( $rows as $row ) {
			self::scan_row( 'users', $row, array( 'user_login', 'user_email', 'user_url', 'display_name' ), $sigs, $state );
		}

		return count( $rows );
	}

	private static function scan_usermeta( $offset, $limit, $sigs, &$state ) {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT umeta_id, user_id, meta_key, meta_value FROM {$wpdb->usermeta}
				ORDER BY umeta_id ASC
				LIMIT %d OFFSET %d",
				$limit,
				$offset
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			return 0;
		}

		foreach ( $rows as $row ) {
			self::scan_row( 'usermeta', $row, array( 'meta_key', 'meta_value' ), $sigs, $state );
		}

		return count( $rows );
	}

	private static function scan_row( $table, $row, $columns, $sigs, &$state ) {
		foreach ( $columns as $column ) {
			if ( ! isset( $row[ $column ] ) ) {
				continue;
			}
			$content = (string) $row[ $column ];
			if ( '' === $content ) {
				continue;
			}

			$max = mvn_db_max_value_bytes();
			if ( strlen( $content ) > $max ) {
				$content = substr( $content, 0, $max );
			}

			$row_key = self::row_key( $table, $row, $column );
			$rel     = 'db:' . $table . ':' . $row_key . ':' . $column;
			$hash    = md5( $content );

			self::run_heuristics( $table, $row, $column, $content, $rel, $hash, $state );
			self::run_signatures( $table, $row, $column, $content, $rel, $hash, $sigs, $state );
		}
	}

	private static function row_key( $table, $row, $column ) {
		switch ( $table ) {
			case 'options':
				return isset( $row['option_name'] ) ? $row['option_name'] : ( isset( $row['option_id'] ) ? $row['option_id'] : '0' );
			case 'posts':
				return isset( $row['ID'] ) ? $row['ID'] : '0';
			case 'postmeta':
				return ( isset( $row['post_id'] ) ? $row['post_id'] : '0' ) . '/' . ( isset( $row['meta_key'] ) ? $row['meta_key'] : '' );
			case 'users':
				return isset( $row['user_login'] ) ? $row['user_login'] : ( isset( $row['ID'] ) ? $row['ID'] : '0' );
			case 'usermeta':
				return ( isset( $row['user_id'] ) ? $row['user_id'] : '0' ) . '/' . ( isset( $row['meta_key'] ) ? $row['meta_key'] : '' );
		}
		return '0';
	}

	private static function run_heuristics( $table, $row, $column, $content, $rel, $hash, &$state ) {
		foreach ( mvn_db_heuristics() as $heur ) {
			if ( empty( $heur['callback'] ) || ! is_callable( $heur['callback'] ) ) {
				continue;
			}
			$detail = call_user_func( $heur['callback'], $table, $row, $column, $content );
			if ( ! $detail ) {
				continue;
			}
			$action = self::action_for( $table, $row, $column, $heur['id'] );
			if ( MVN_Scanner::add_finding(
				$state,
				array(
					'source'   => 'db',
					'table'    => $table,
					'row_id'   => self::row_id( $table, $row ),
					'column'   => $column,
					'row_key'  => self::row_key( $table, $row, $column ),
					'rel'      => $rel,
					'sig'      => $heur['id'],
					'label'    => $heur['label'],
					'severity' => $heur['severity'],
					'detail'   => is_string( $detail ) ? $detail : '',
					'action'   => $action,
					'clean'    => 'none',
					'snippet'  => self::snippet( $content, 0, 200 ),
				),
				$content,
				$hash
			) ) {
				self::bump_stats( $state, $heur['severity'] );
			}
		}
	}

	private static function run_signatures( $table, $row, $column, $content, $rel, $hash, $sigs, &$state ) {
		// Serialized plugin blobs: only allow high-confidence executable malware signatures.
		$serialized = function_exists( 'is_serialized' ) && is_serialized( $content );
		$allow_on_serialized = array(
			'eval_decoder',
			'eval_request',
			'nested_decoders',
			'shell_exec_request',
			'webshell_markers',
			'preg_replace_e',
		);

		$scope_hint = self::scope_hint( $column, $content );

		foreach ( $sigs as $sig ) {
			if ( 'htaccess' === $sig['scope'] || 'ini' === $sig['scope'] ) {
				continue;
			}
			// SVG signatures only belong on real SVG markup — not FAQ <script type="ld+json">.
			if ( 'svg' === $sig['scope'] && ! preg_match( '/<svg[\s>]/i', $content ) ) {
				continue;
			}
			if ( $serialized && ! in_array( $sig['id'], $allow_on_serialized, true ) ) {
				continue;
			}
			// File PHP signatures on option/meta values cause mass FPs (base64 in Freemius, RevSlider…).
			if ( in_array( $column, array( 'option_value', 'meta_value' ), true ) && 'php' === $sig['scope'] ) {
				if ( ! in_array( $sig['id'], $allow_on_serialized, true ) ) {
					continue;
				}
			}
			if ( 'php' === $sig['scope'] && 'php' !== $scope_hint && 'any' !== $scope_hint ) {
				continue;
			}
			if ( 'js' === $sig['scope'] && 'js' !== $scope_hint && 'any' !== $scope_hint ) {
				continue;
			}
			if ( @preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$offset = isset( $m[0][1] ) ? (int) $m[0][1] : 0;
				$match  = isset( $m[0][0] ) ? $m[0][0] : '';
				if ( MVN_Scanner::is_db_false_positive( $sig['id'], $table, $row, $column, $content, $offset, $match ) ) {
					continue;
				}
				// Only auto-clean HTML/JS injections in posts — not opaque option blobs.
				$action = 'db_review';
				if ( in_array( $column, array( 'post_content', 'post_excerpt', 'post_title' ), true ) && 'none' !== $sig['clean'] ) {
					$action = 'db_clean';
				} elseif ( in_array( $sig['id'], $allow_on_serialized, true ) && false !== strpos( $content, '<?php' ) ) {
					$action = 'db_clean';
				}
				if ( MVN_Scanner::add_finding(
					$state,
					array(
						'source'   => 'db',
						'table'    => $table,
						'row_id'   => self::row_id( $table, $row ),
						'column'   => $column,
						'row_key'  => self::row_key( $table, $row, $column ),
						'rel'      => $rel,
						'sig'      => $sig['id'],
						'label'    => $sig['label'],
						'severity' => $sig['severity'],
						'detail'   => 'تطابق در ستون ' . $column,
						'action'   => $action,
						'clean'    => $sig['clean'],
						'snippet'  => self::snippet( $content, $offset, 220 ),
					),
					$content,
					$hash
				) ) {
					self::bump_stats( $state, $sig['severity'] );
				}
			}
		}
	}

	private static function scope_hint( $column, $content ) {
		if ( in_array( $column, array( 'post_content', 'option_value', 'meta_value' ), true ) ) {
			if ( preg_match( '/<script/i', $content ) ) {
				return 'js';
			}
			if ( preg_match( '/<\?php|\beval\s*\(|\bbase64_decode\s*\(/i', $content ) ) {
				return 'php';
			}
		}
		return 'any';
	}

	private static function row_id( $table, $row ) {
		switch ( $table ) {
			case 'options':
				return isset( $row['option_id'] ) ? (int) $row['option_id'] : 0;
			case 'posts':
				return isset( $row['ID'] ) ? (int) $row['ID'] : 0;
			case 'postmeta':
				return isset( $row['meta_id'] ) ? (int) $row['meta_id'] : 0;
			case 'users':
				return isset( $row['ID'] ) ? (int) $row['ID'] : 0;
			case 'usermeta':
				return isset( $row['umeta_id'] ) ? (int) $row['umeta_id'] : 0;
		}
		return 0;
	}

	private static function action_for( $table, $row, $column, $sig_id ) {
		if ( 'db_hidden_admin' === $sig_id || 'db_admin_capability' === $sig_id || 'db_ghost_admin' === $sig_id ) {
			return 'db_review';
		}
		if ( 'options' === $table && 'option_name' === $column
			&& in_array( $sig_id, array( 'db_rogue_option_name', 'db_malware_tracker_option' ), true ) ) {
			$name = isset( $row['option_name'] ) ? $row['option_name'] : '';
			if ( ! in_array( $name, mvn_db_protected_options(), true ) ) {
				return 'db_delete_option';
			}
		}
		if ( 'usermeta' === $table && 'db_malware_tracker_usermeta' === $sig_id ) {
			return 'db_review';
		}
		if ( in_array( $column, array( 'post_content', 'post_excerpt' ), true ) ) {
			return 'db_clean';
		}
		// Serialized / opaque options: review only — never auto "db_clean".
		return 'db_review';
	}

	private static function bump_stats( &$state, $severity ) {
		if ( isset( $state['stats'][ $severity ] ) ) {
			$state['stats'][ $severity ]++;
		}
		if ( ! isset( $state['stats']['db'] ) ) {
			$state['stats']['db'] = 0;
		}
		$state['stats']['db']++;
	}

	private static function snippet( $content, $offset, $len ) {
		$start = max( 0, $offset - 40 );
		$chunk = substr( $content, $start, $len );
		$chunk = preg_replace( '/\s+/', ' ', $chunk );
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $chunk, 0, $len );
		}
		return substr( $chunk, 0, $len );
	}
}
