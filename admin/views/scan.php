<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="mvn-card">
	<h2>اسکن بدافزار</h2>
	<p>اسکنر فایل‌های PHP / JS / HTML، تمام <code>.htaccess</code> ها، و در صورت فعال بودن، <strong>دیتابیس</strong> (options، posts، users) را برای بدافزار پنهان بررسی می‌کند.</p>

	<div class="mvn-form-row">
		<label>محدوده اسکن</label>
		<select id="mvn-scan-scope">
			<option value="all">همه (هسته + wp-content)</option>
			<option value="wp-content">فقط wp-content (پلاگین/قالب/آپلود)</option>
			<option value="core">فقط هسته وردپرس (wp-admin / wp-includes)</option>
		</select>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-deep" value="1"> اسکن عمیق (فایل‌های بدون پسوند هم بررسی شوند)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-core" value="1" checked> بررسی checksum هسته (MD5 رسمی wordpress.org)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-db" value="1" checked> اسکن دیتابیس (options / posts / users — کشف بدافزار پنهان)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-incremental" value="1" checked> اسکن افزایشی (پرش از فایل‌های سالم و بدون تغییر)</label>
	</div>
	<div class="mvn-form-row">
		<label><input type="checkbox" id="mvn-scan-full" value="1"> اسکن کامل (بدون کش — همه فایل‌ها مجدداً بررسی شوند)</label>
	</div>

	<div class="mvn-actions">
		<button type="button" class="button button-primary button-hero" id="mvn-scan-start">شروع اسکن</button>
	</div>

	<div id="mvn-scan-progress" class="mvn-progress-wrap" style="display:none;margin-top:20px">
		<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-scan-bar" style="width:0%"></div></div>
		<div class="mvn-progress-meta">
			<span id="mvn-scan-label">آماده‌سازی...</span>
			<span id="mvn-scan-pct">0%</span>
		</div>
		<div class="mvn-stats-inline" id="mvn-scan-stats"></div>
	</div>

	<div id="mvn-scan-result" style="display:none;margin-top:16px"></div>
</div>
