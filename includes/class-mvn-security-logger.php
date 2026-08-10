<?php
/**
 * Security migration logger — never logs secrets.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Security_Logger {

	/** @var string Absolute log file path. */
	private $file;

	/**
	 * @param string $file Absolute path.
	 */
	public function __construct( $file ) {
		$this->file = (string) $file;
	}

	/**
	 * @param string $message Safe message (no secrets).
	 */
	public function info( $message ) {
		$this->write( 'INFO', $message );
	}

	/**
	 * @param string $message Safe message.
	 */
	public function warn( $message ) {
		$this->write( 'WARN', $message );
	}

	/**
	 * @param string $message Safe message.
	 */
	public function error( $message ) {
		$this->write( 'ERROR', $message );
	}

	/**
	 * @return string[]
	 */
	public function read_lines( $limit = 200 ) {
		if ( ! is_file( $this->file ) ) {
			return array();
		}
		$lines = @file( $this->file, FILE_IGNORE_NEW_LINES );
		if ( ! is_array( $lines ) ) {
			return array();
		}
		$limit = max( 1, (int) $limit );
		return array_slice( $lines, -$limit );
	}

	/**
	 * @return string
	 */
	public function path() {
		return $this->file;
	}

	/**
	 * Redact obvious secret patterns before writing.
	 *
	 * @param string $message Raw message.
	 * @return string
	 */
	public static function redact( $message ) {
		$message = (string) $message;
		$message = preg_replace( '/(password|passwd|pwd|secret|salt|auth_key|secure_auth_key|logged_in_key|nonce_key|auth_salt|secure_auth_salt|logged_in_salt|nonce_salt|api[_-]?key|token|authorization)\s*[:=]\s*\S+/i', '$1=[REDACTED]', $message );
		$message = preg_replace( '/\b(sk|pk|ghp|glpat)_[A-Za-z0-9]+\b/', '[REDACTED]', $message );
		return $message;
	}

	/**
	 * @param string $level   INFO|WARN|ERROR.
	 * @param string $message Message.
	 */
	private function write( $level, $message ) {
		$dir = dirname( $this->file );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$line = '[' . gmdate( 'H:i:s' ) . '] [' . $level . '] ' . self::redact( $message ) . "\n";
		@file_put_contents( $this->file, $line, FILE_APPEND | LOCK_EX );
		if ( 'ERROR' === $level || 'WARN' === $level ) {
			mvn_log( 'SecurityMigration ' . $level . ': ' . self::redact( $message ) );
		}
	}
}
