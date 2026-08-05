<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="mvn-grid mvn-grid-2">
	<div class="mvn-card">
		<h2>تعمیر فایل‌های هسته وردپرس</h2>
		<p>
			فایل‌های <code>wp-admin</code>، <code>wp-includes</code> و فایل‌های ریشه هسته از
			<code>wordpress_core.zip</code> داخل پلاگین استخراج و جایگزین می‌شوند.
			<strong>wp-config.php</strong> و کل پوشه <strong>wp-content</strong> دست‌نخورده می‌مانند.
		</p>
		<ul class="mvn-kv">
			<li>
				<span>وضعیت آرشیو</span>
				<b class="<?php echo ! empty( $core['zip_ok'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( empty( $core['exists'] ) ) {
						echo 'فایل zip موجود نیست';
					} elseif ( empty( $core['zip_ok'] ) ) {
						echo 'آرشیو باز نمی‌شود';
					} else {
						echo 'آماده — ' . (int) $core['files'] . ' ورودی / ' . esc_html( mvn_size_format( $core['size'] ) );
					}
					?>
				</b>
			</li>
		</ul>
		<button type="button" class="button button-primary button-hero" id="mvn-core-start" <?php disabled( empty( $core['zip_ok'] ) ); ?>>
			شروع جایگزینی هسته
		</button>
		<div id="mvn-core-progress" class="mvn-progress-wrap" style="display:none;margin-top:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-core-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta">
				<span id="mvn-core-label">...</span>
				<span id="mvn-core-pct">0%</span>
			</div>
		</div>
		<div id="mvn-core-result" style="margin-top:12px"></div>
	</div>

	<div class="mvn-card">
		<h2>بازیابی .htaccess ریشه</h2>
		<p>فایل ریشه سایت با نسخه سالم <code>sources/default.htaccess</code> جایگزین می‌شود. نسخه فعلی قبل از جایگزینی قرنطینه می‌گردد.</p>
		<ul class="mvn-kv">
			<li>
				<span>وضعیت فعلی</span>
				<b class="<?php echo ! empty( $ht['matches'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( empty( $ht['exists'] ) ) {
						echo 'وجود ندارد';
					} elseif ( ! empty( $ht['matches'] ) ) {
						echo 'مطابق پیش‌فرض';
					} else {
						echo 'متفاوت از پیش‌فرض';
					}
					?>
				</b>
			</li>
		</ul>
		<button type="button" class="button button-primary" id="mvn-ht-restore">بازیابی htaccess ریشه</button>
		<div id="mvn-ht-restore-result" style="margin-top:10px"></div>
	</div>
</div>

<div class="mvn-grid mvn-grid-2" style="margin-top:16px">
	<div class="mvn-card">
		<h2>پاکسازی .htaccess های جعلی</h2>
		<p>
			ویروس جدید در تک‌تک پوشه‌ها یک <code>.htaccess</code> می‌سازد.
			این ابزار همه htaccess های غیرریشه که حاوی PHP-handler / Rewrite مخرب هستند را (بعد از قرنطینه) حذف می‌کند.
		</p>
		<div class="mvn-form-row">
			<label><input type="checkbox" id="mvn-ht-aggressive" value="1"> حالت تهاجمی: حذف همه htaccess غیرریشه (به‌جز deny-php امن در uploads)</label>
		</div>
		<button type="button" class="button button-primary" id="mvn-ht-purge">حذف htaccess های جعلی</button>
		<div id="mvn-ht-purge-result" style="margin-top:10px"></div>
	</div>

	<div class="mvn-card">
		<h2>اصلاح سطح دسترسی‌ها (Permissions)</h2>
		<p>
			پوشه‌ها → <code>755</code>، فایل‌ها → <code>644</code>، و <code>wp-config.php</code> → <code>600</code>.
			روی هاست‌های ویندوز/IIS ممکن است chmod اثر واقعی نداشته باشد.
		</p>
		<button type="button" class="button button-primary" id="mvn-perms-start">اصلاح سطح دسترسی‌ها</button>
		<div id="mvn-perms-progress" class="mvn-progress-wrap" style="display:none;margin-top:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-perms-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta">
				<span id="mvn-perms-label">...</span>
				<span id="mvn-perms-pct">0%</span>
			</div>
		</div>
		<div id="mvn-perms-result" style="margin-top:10px"></div>
	</div>
</div>
