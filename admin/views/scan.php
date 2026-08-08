<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$scan_status = ( is_array( $state ) && ! empty( $state['status'] ) ) ? $state['status'] : 'idle';
$is_active   = in_array( $scan_status, array( 'running', 'paused' ), true );
?>
<div class="mvn-card">
	<h2>اسکن بدافزار</h2>
	<p>
		اسکنر فایل‌های PHP / JS / HTML، رسانه‌های uploads (پلی‌گلوت)، <code>.htaccess</code>،
		<code>.user.ini</code>، drop-inها، و در صورت فعال بودن checksum هسته / پلاگین‌قالب مخزن، دیتابیس و Action Scheduler را بررسی می‌کند.
	</p>

	<?php
	$sig_pack = isset( $sig_pack ) && is_array( $sig_pack ) ? $sig_pack : array();
	?>
	<div class="mvn-card" style="margin:0 0 16px;background:#f8fafc">
		<h3 style="margin-top:0">بسته امضا (Signature Pack)</h3>
		<ul class="mvn-kv">
			<li>
				<span>نسخه فعال</span>
				<b><?php echo esc_html( isset( $sig_pack['version'] ) ? $sig_pack['version'] : '—' ); ?></b>
			</li>
			<li>
				<span>منبع</span>
				<b><?php echo esc_html( isset( $sig_pack['source'] ) ? $sig_pack['source'] : '—' ); ?></b>
			</li>
			<li>
				<span>امضاهای اضافه / هش</span>
				<b><?php echo (int) ( isset( $sig_pack['sig_count'] ) ? $sig_pack['sig_count'] : 0 ); ?> / <?php echo (int) ( isset( $sig_pack['hash_count'] ) ? $sig_pack['hash_count'] : 0 ); ?></b>
			</li>
		</ul>
		<div class="mvn-actions">
			<button type="button" class="button" id="mvn-sig-pack-update">
				<?php echo ! empty( $sig_pack['has_remote'] ) ? 'دریافت به‌روزرسانی امضا' : 'همگام‌سازی با بسته همراه پلاگین'; ?>
			</button>
		</div>
		<p class="mvn-muted" style="margin-top:8px">
			برای آپدیت آنلاین، ثابت <code>MVN_SIGNATURE_PACK_URL</code> یا فیلتر <code>mvn_signature_pack_url</code> را تنظیم کنید.
		</p>
		<div id="mvn-sig-pack-result" style="margin-top:8px"></div>
	</div>

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
		<label><input type="checkbox" id="mvn-scan-repo" value="1" checked <?php disabled( $is_active ); ?>> بررسی checksum پلاگین/قالب مخزن wordpress.org</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-media" value="1" checked <?php disabled( $is_active ); ?>> اسکن پلی‌گلوت رسانه در uploads (PHP داخل jpg/gif/ico/...)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-db" value="1" checked <?php disabled( $is_active ); ?>> اسکن دیتابیس (options / posts / users — کشف بدافزار پنهان)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-as" value="1" checked <?php disabled( $is_active ); ?>> اسکن Action Scheduler (اقدامات زمان‌بندی‌شده مشکوک)</label>
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

<?php
$as_meta  = isset( $as_meta ) && is_array( $as_meta ) ? $as_meta : array();
$as_state = isset( $as_state ) && is_array( $as_state ) ? $as_state : array();
$as_avail = ! empty( $as_meta['available'] );
$as_count = isset( $as_meta['count'] ) ? (int) $as_meta['count'] : 0;
$as_status = ( ! empty( $as_state['status'] ) ) ? $as_state['status'] : 'idle';
$as_running = ( 'running' === $as_status );
?>
<div class="mvn-card" style="margin-top:20px">
	<h2>اسکن Action Scheduler</h2>
	<p>
		اقدامات زمان‌بندی‌شده (جداول <code>actionscheduler_*</code>) را برای hookها و آرگومان‌های مشکوک بررسی می‌کند.
		یافته‌ها در صفحه رفع مشکلات قابل حذف و قرنطینه هستند.
	</p>
	<ul class="mvn-kv">
		<li>
			<span>وضعیت جداول</span>
			<b><?php echo $as_avail ? 'موجود' : 'یافت نشد'; ?></b>
		</li>
		<?php if ( $as_avail ) : ?>
		<li>
			<span>تعداد actionها</span>
			<b id="mvn-as-count"><?php echo (int) $as_count; ?></b>
		</li>
		<?php endif; ?>
	</ul>
	<?php if ( ! $as_avail ) : ?>
		<p class="mvn-muted">این سایت جدول Action Scheduler ندارد (معمولاً با ووکامرس یا پلاگین Action Scheduler نصب می‌شود).</p>
	<?php else : ?>
		<div class="mvn-actions">
			<button type="button" class="button button-primary" id="mvn-as-scan-start" <?php disabled( $as_running || $is_active ); ?>>شروع اسکن Action Scheduler</button>
			<button type="button" class="button button-link-delete" id="mvn-as-purge-all" <?php disabled( $as_running || $is_active || $as_count <= 0 ); ?>>پاکسازی همه actionscheduler_actions</button>
		</div>
		<p class="mvn-muted" style="margin-top:8px">
			پاکسازی همه: کل ردیف‌های <code>actionscheduler_actions</code> به‌همراه لاگ‌ها و claimها حذف می‌شوند.
			یک خلاصه (نمونه) در قرنطینه ذخیره می‌شود. پلاگین‌هایی مثل ووکامرس در صورت نیاز actionهای جدید را دوباره زمان‌بندی می‌کنند.
		</p>
		<div id="mvn-as-scan-progress" class="mvn-progress-wrap" style="<?php echo $as_running ? '' : 'display:none'; ?>margin-top:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-as-scan-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta">
				<span id="mvn-as-scan-label">آماده‌سازی...</span>
				<span id="mvn-as-scan-pct">0%</span>
			</div>
		</div>
		<div id="mvn-as-scan-result" style="margin-top:12px"></div>
	<?php endif; ?>
</div>
<script type="text/javascript">
window.MVN_SCAN_BOOT = <?php echo wp_json_encode( array( 'status' => $scan_status ) ); ?>;
</script>
