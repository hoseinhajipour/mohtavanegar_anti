<?php
/**
 * Safe remediation pipeline: Dry Run → Persistence-first quarantine → verify.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Remediation {

	/**
	 * Build a dry-run plan for an incident / finding id.
	 *
	 * @param string $issue_id Finding id.
	 * @return array|WP_Error
	 */
	public static function preview( $issue_id ) {
		$issue = self::find_issue( $issue_id );
		if ( ! $issue ) {
			return new WP_Error( 'not_found', 'یافته یافت نشد.' );
		}
		$steps = array();
		$persist = isset( $issue['persistence'] ) && is_array( $issue['persistence'] ) ? $issue['persistence'] : array();

		foreach ( $persist as $p ) {
			if ( empty( $p['type'] ) || empty( $p['path'] ) ) {
				continue;
			}
			if ( 'file' === $p['type'] && (int) ( isset( $p['risk_score'] ) ? $p['risk_score'] : 0 ) >= 60 ) {
				$steps[] = array(
					'op'     => 'quarantine',
					'target' => $p['path'],
					'why'    => 'persistence_source',
				);
			}
			if ( 'cron' === $p['type'] ) {
				$steps[] = array(
					'op'     => 'disable_cron',
					'target' => $p['path'],
					'why'    => 'persistence_cron',
				);
			}
		}

		$action = isset( $issue['action'] ) ? $issue['action'] : '';
		$rel    = isset( $issue['rel'] ) ? $issue['rel'] : '';
		if ( 'persist_disable_cron' === $action && ! empty( $issue['cron_hook'] ) ) {
			$steps[] = array( 'op' => 'disable_cron', 'target' => $issue['cron_hook'], 'why' => 'cron_hook' );
		} elseif ( 'persist_delete_option' === $action || 'db_delete_option' === $action ) {
			$steps[] = array( 'op' => 'delete_option', 'target' => $rel, 'why' => 'tracker_option' );
		} elseif ( in_array( $action, array( 'quarantine', 'quarantine_delete' ), true ) && 0 !== strpos( $rel, 'db:' ) && 0 !== strpos( $rel, 'cron:' ) ) {
			$steps[] = array( 'op' => 'quarantine', 'target' => $rel, 'why' => 'malware_file' );
		}

		return array(
			'dry_run'  => true,
			'issue_id' => $issue_id,
			'issue'    => array(
				'rel'        => $rel,
				'sig'        => isset( $issue['sig'] ) ? $issue['sig'] : '',
				'label'      => isset( $issue['label'] ) ? $issue['label'] : '',
				'risk_score' => isset( $issue['risk_score'] ) ? $issue['risk_score'] : ( isset( $issue['confidence'] ) ? $issue['confidence'] : 0 ),
			),
			'steps'    => $steps,
			'lines'    => array_map(
				static function ( $s ) {
					return 'Would ' . $s['op'] . ': ' . $s['target'] . ' (' . $s['why'] . ')';
				},
				$steps
			),
		);
	}

	/**
	 * Execute remediation after dry-run confirmation (persistence first).
	 *
	 * @param string $issue_id Finding id.
	 * @param bool   $dry_run  If true, only preview.
	 * @return array|WP_Error
	 */
	public static function apply( $issue_id, $dry_run = false ) {
		$plan = self::preview( $issue_id );
		if ( is_wp_error( $plan ) ) {
			return $plan;
		}
		if ( $dry_run ) {
			return $plan;
		}

		$done   = array();
		$errors = array();
		// Persistence-ish steps first.
		usort(
			$plan['steps'],
			static function ( $a, $b ) {
				$rank = array( 'disable_cron' => 1, 'delete_option' => 2, 'quarantine' => 3 );
				$ra   = isset( $rank[ $a['op'] ] ) ? $rank[ $a['op'] ] : 9;
				$rb   = isset( $rank[ $b['op'] ] ) ? $rank[ $b['op'] ] : 9;
				return $ra - $rb;
			}
		);

		foreach ( $plan['steps'] as $step ) {
			$r = self::run_step( $step, $issue_id );
			if ( is_wp_error( $r ) ) {
				$errors[] = $step['op'] . ' ' . $step['target'] . ': ' . $r->get_error_message();
			} else {
				$done[] = $step;
			}
		}

		MVN_Security_Log::write( 'remediation_apply', $issue_id, empty( $errors ) ? 'ok' : 'partial' );

		// Watch malware path for reinfection.
		$issue = self::find_issue( $issue_id );
		if ( $issue && ! empty( $issue['rel'] ) && 0 !== strpos( $issue['rel'], 'db:' ) && 0 !== strpos( $issue['rel'], 'cron:' ) ) {
			MVN_Reinfection_Monitor::watch( $issue['rel'], $issue_id );
		}

		return array(
			'dry_run' => false,
			'done'    => $done,
			'errors'  => $errors,
			'watched' => ! empty( $issue['rel'] ) ? $issue['rel'] : '',
		);
	}

	private static function run_step( $step, $issue_id ) {
		$op     = isset( $step['op'] ) ? $step['op'] : '';
		$target = isset( $step['target'] ) ? $step['target'] : '';

		switch ( $op ) {
			case 'quarantine':
				if ( class_exists( 'MVN_Cleaner' ) && method_exists( 'MVN_Cleaner', 'is_protected_live_path' ) && MVN_Cleaner::is_protected_live_path( $target ) ) {
					return new WP_Error( 'protected', 'مسیر حیاتی ایزوله نمی‌شود.' );
				}
				$result = MVN_Quarantine::isolate( $target, array( 'reason' => 'remediation', 'issue_id' => $issue_id ) );
				if ( is_wp_error( $result ) ) {
					return $result;
				}
				MVN_File_Hash_Store::mark_status( $target, 'quarantined' );
				MVN_Security_Log::write( 'file_quarantined', $target, (string) $result );
				return true;

			case 'disable_cron':
				$hook = sanitize_text_field( $target );
				if ( ! $hook ) {
					return new WP_Error( 'bad_hook', 'hook نامعتبر' );
				}
				$backup = array( 'hook' => $hook, 'cron' => _get_cron_array() );
				MVN_Quarantine::store_text( 'cron:' . $hook, wp_json_encode( $backup ), array( 'reason' => 'cron-disable' ) );
				wp_unschedule_hook( $hook );
				MVN_Security_Log::write( 'cron_removed', $hook, 'ok' );
				return true;

			case 'delete_option':
				// Resolve option name from rel db:options:NAME:...
				$name = $target;
				if ( preg_match( '/^db:options:([^:]+)/', $target, $m ) ) {
					$name = $m[1];
				}
				if ( in_array( $name, mvn_db_protected_options(), true ) ) {
					return new WP_Error( 'protected', 'option محافظت‌شده' );
				}
				$val = get_option( $name, null );
				MVN_Quarantine::store_text(
					'db:options:' . $name,
					wp_json_encode( array( 'option_name' => $name, 'option_value' => $val ) ),
					array( 'reason' => 'option-delete' )
				);
				delete_option( $name );
				MVN_Security_Log::write( 'option_removed', $name, 'ok' );
				return true;
		}

		return new WP_Error( 'unknown_op', 'عمل ناشناخته' );
	}

	private static function find_issue( $issue_id ) {
		$issues = class_exists( 'MVN_Incidents' ) ? MVN_Incidents::issues() : MVN_Scanner::get_issues();
		foreach ( (array) $issues as $issue ) {
			if ( isset( $issue['id'] ) && $issue['id'] === $issue_id ) {
				return $issue;
			}
		}
		return null;
	}
}
