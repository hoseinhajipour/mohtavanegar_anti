<?php
/**
 * Bounded archive inspection with zip-slip and bomb guards.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MVN_Archive_Scanner {

	const MAX_ARCHIVE_BYTES = 134217728;
	const MAX_ENTRIES       = 5000;
	const MAX_EXPANDED      = 536870912;
	const MAX_ENTRY_BYTES   = 8388608;
	const MAX_DEPTH         = 12;
	const MAX_RATIO         = 100;

	/**
	 * Scan a ZIP/TAR without extracting it.
	 *
	 * @param string $abs Absolute path.
	 * @param string $rel Relative path.
	 * @return array[]
	 */
	public static function scan( $abs, $rel ) {
		if ( ! is_file( $abs ) || filesize( $abs ) > self::MAX_ARCHIVE_BYTES ) {
			return array();
		}
		$ext = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
		if ( 'zip' === $ext && class_exists( 'ZipArchive' ) ) {
			return self::scan_zip( $abs, $rel );
		}
		if ( in_array( $ext, array( 'tar', 'gz', 'tgz' ), true ) && class_exists( 'PharData' ) ) {
			return self::scan_tar( $abs, $rel );
		}
		return array();
	}

	private static function finding( $rel, $sig, $label, $confidence, $detail ) {
		return array(
			'rel' => $rel, 'sig' => $sig, 'label' => $label,
			'severity' => $confidence >= 95 ? 'critical' : 'warning',
			'detail' => $detail, 'action' => 'manual_review',
			'confidence' => $confidence, 'source' => 'archive',
			'evidence' => array( array( 'engine' => 'archive', 'signal' => $sig ) ),
		);
	}

	private static function unsafe_name( $name ) {
		$name = str_replace( '\\', '/', (string) $name );
		return '' === $name
			|| '/' === substr( $name, 0, 1 )
			|| preg_match( '#^[A-Za-z]:/#', $name )
			|| false !== strpos( '/' . $name . '/', '/../' )
			|| substr_count( trim( $name, '/' ), '/' ) > self::MAX_DEPTH;
	}

	private static function inspect_payload( $archive_rel, $entry, $content ) {
		$out = array();
		$virtual = $archive_rel . '::' . $entry;
		if ( preg_match( '/\.(?:php\d*|phtml|pht|inc)$/i', $entry ) && 0 === strpos( $archive_rel, 'wp-content/uploads/' ) ) {
			$out[] = self::finding( $virtual, 'php_in_upload_archive', 'فایل PHP داخل آرشیو uploads', 96, 'اجرای مستقیم نیست؛ آرشیو را پیش از استخراج بررسی کنید.' );
		}
		$hash = MVN_Signature_Pack::match_hash( $content );
		if ( $hash ) {
			$out[] = self::finding( $virtual, 'archive_known_malware_hash', 'هش بدافزار داخل آرشیو', 99, $hash['label'] );
		}
		if ( preg_match( '/<\?php/i', $content ) && preg_match( '/(?:eval|assert|system|shell_exec)\s*\([^;]{0,400}(?:base64_decode|\$_(?:POST|GET|REQUEST))/is', $content ) ) {
			$out[] = self::finding( $virtual, 'archive_php_payload', 'payload اجرایی مشکوک داخل آرشیو', 95, 'ترکیب execution و decoder/input شناسایی شد.' );
		}
		return $out;
	}

	private static function scan_zip( $abs, $rel ) {
		$out = array();
		$zip = new ZipArchive();
		if ( true !== $zip->open( $abs ) ) {
			return $out;
		}
		if ( $zip->numFiles > self::MAX_ENTRIES ) {
			$zip->close();
			return array( self::finding( $rel, 'archive_entry_limit', 'آرشیو با تعداد entry غیرعادی', 85, 'بیش از سقف ' . self::MAX_ENTRIES ) );
		}
		$expanded = 0;
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$stat = $zip->statIndex( $i );
			$name = isset( $stat['name'] ) ? $stat['name'] : '';
			if ( self::unsafe_name( $name ) ) {
				$out[] = self::finding( $rel . '::' . $name, 'archive_zip_slip', 'مسیر ناامن داخل آرشیو (zip-slip)', 99, $name );
				continue;
			}
			$size       = isset( $stat['size'] ) ? (int) $stat['size'] : 0;
			$compressed = max( 1, isset( $stat['comp_size'] ) ? (int) $stat['comp_size'] : 1 );
			$expanded  += $size;
			if ( $expanded > self::MAX_EXPANDED || $size / $compressed > self::MAX_RATIO ) {
				$out[] = self::finding( $rel, 'archive_bomb', 'احتمال archive bomb', 92, 'expanded size/compression ratio از سقف عبور کرد.' );
				break;
			}
			if ( $size <= 0 || $size > self::MAX_ENTRY_BYTES || ! preg_match( '/\.(?:php\d*|phtml|pht|inc|js|html?)$/i', $name ) ) {
				continue;
			}
			$content = $zip->getFromIndex( $i, self::MAX_ENTRY_BYTES );
			if ( false !== $content ) {
				$out = array_merge( $out, self::inspect_payload( $rel, $name, $content ) );
			}
		}
		$zip->close();
		return $out;
	}

	private static function scan_tar( $abs, $rel ) {
		$out = array();
		try {
			$phar = new PharData( $abs );
			$count = 0;
			$total = 0;
			foreach ( new RecursiveIteratorIterator( $phar ) as $file ) {
				$count++;
				$name = str_replace( 'phar://' . str_replace( '\\', '/', $abs ) . '/', '', str_replace( '\\', '/', $file->getPathname() ) );
				$size = (int) $file->getSize();
				$total += $size;
				if ( $count > self::MAX_ENTRIES || $total > self::MAX_EXPANDED ) {
					$out[] = self::finding( $rel, 'archive_bomb', 'سقف ایمنی TAR رد شد', 92, 'entry/expanded limit' );
					break;
				}
				if ( self::unsafe_name( $name ) ) {
					$out[] = self::finding( $rel . '::' . $name, 'archive_zip_slip', 'مسیر ناامن داخل TAR', 99, $name );
				} elseif ( $size > 0 && $size <= self::MAX_ENTRY_BYTES && preg_match( '/\.(?:php\d*|phtml|pht|inc)$/i', $name ) ) {
					$content = @file_get_contents( $file->getPathname(), false, null, 0, self::MAX_ENTRY_BYTES );
					if ( false !== $content ) {
						$out = array_merge( $out, self::inspect_payload( $rel, $name, $content ) );
					}
				}
			}
		} catch ( Exception $e ) {
			$out[] = self::finding( $rel, 'archive_parse_error', 'خطا در تحلیل امن آرشیو', 45, $e->getMessage() );
		}
		return $out;
	}
}
