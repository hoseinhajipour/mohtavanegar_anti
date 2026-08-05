<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$scan_status = ( is_array( $state ) && ! empty( $state['status'] ) ) ? $state['status'] : 'idle';
$is_active   = in_array( $scan_status, array( 'running', 'paused' ), true );
?>
<div class="mvn-card">
	<h2>اسکن بدافزار</h2>
	<p>اسکنر فایل‌های PHP / JS / HTML، تمام <code>.htaccess</code> ها، و در صورت فعال بودن، <strong>دیتابیس</strong> (options، posts، users) را برای بدافزار پنهان بررسی می‌کند.</p>

	<div class="mvn-form-row">
		<label>محدوده اسکن</label>
		<select id="mvn-scan-scope" <?php disabled( $is_active ); ?>>
			<option value="all">همه (هسته + wp-content)</option>
			<option value="wp-content">فقط wp-content (پلاگین/قالب/آپلود)</option>
			<option value="core">فقط هسته وردپرس (wp-admin / wp-includes)</option>
		</select>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-deep" value="1" <?php disabled( $is_active ); ?>> اسکن عمیق (فایل‌های بدون پسوند هم بررسی شوند)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-core" value="1" checked <?php disabled( $is_active ); ?>> بررسی checksum هسته (MD5 رسمی wordpress.org)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-db" value="1" checked <?php disabled( $is_active ); ?>> اسکن دیتابیس (options / posts / users — کشف بدافزار پنهان)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-incremental" value="1" checked <?php disabled( $is_active ); ?>> اسکن افزایشی (پرش از فایل‌های سالم و بدون تغییر)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-full" value="1" <?php disabled( $is_active ); ?>> اسکن کامل (بدون کش — همه فایل‌ها مجدداً بررسی شوند)</label>
	</div>

	<div class="mvn-actions mvn-scan-actions">
		<button type="button" class="button button-primary button-hero" id="mvn-scan-start" <?php disabled( $is_active ); ?>>شروع اسکن</button>
		<button type="button" class="button" id="mvn-scan-pause" style="<?php echo ( 'running' === $scan_status ) ? '' : 'display:none'; ?>">توقف موقت</button>
		<button type="button" class="button button-primary" id="mvn-scan-resume" style="<?php echo ( 'paused' === $scan_status ) ? '' : 'display:none'; ?>">ادامه اسکن</button>
		<button type="button" class="button button-link-delete" id="mvn-scan-stop" style="<?php echo $is_active ? '' : 'display:none'; ?>">توقف کامل</button>
	</div>

	<div id="mvn-scan-progress" class="mvn-progress-wrap" style="<?php echo $is_active ? '' : 'display:none'; ?>margin-top:20px">
		<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-scan-bar" style="width:<?php echo ( $is_active && ! empty( $state['total'] ) ) ? (int) min( 100, round( ( (int) $state['processed'] / (int) $state['total'] ) * 100 ) ) : 0; ?>%"></div></div>
		<div class="mvn-progress-meta">
			<span id="mvn-scan-label">
				<?php
				if ( 'paused' === $scan_status ) {
					echo 'متوقف موقت — بررسی‌شده: ' . (int) ( isset( $state['processed'] ) ? $state['processed'] : 0 ) . ' / ' . (int) ( isset( $state['total'] ) ? $state['total'] : 0 );
				} elseif ( 'running' === $scan_status ) {
					echo 'در حال اسکن...';
				} else {
					echo 'آماده‌سازی...';
				}
				?>
			</span>
			<span id="mvn-scan-pct"><?php echo ( $is_active && ! empty( $state['total'] ) ) ? (int) min( 100, round( ( (int) $state['processed'] / (int) $state['total'] ) * 100 ) ) : 0; ?>%</span>
		</div>
		<div class="mvn-stats-inline" id="mvn-scan-stats"></div>
	</div>

	<div id="mvn-scan-result" style="display:none;margin-top:16px"></div>
</div>
<script type="text/javascript">
window.MVN_SCAN_BOOT = <?php echo wp_json_encode( array( 'status' => $scan_status ) ); ?>;
</script>
