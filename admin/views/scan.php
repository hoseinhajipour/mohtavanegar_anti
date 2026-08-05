<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="mvn-card">
	<h2>اسکن بدافزار</h2>
	<p>اسکنر فایل‌های PHP / JS / HTML و تمام <code>.htaccess</code> های سایت را برای کد تزریق‌شده، وب‌شل، و الگوی ویروس htaccess جعلی بررسی می‌کند.</p>

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
