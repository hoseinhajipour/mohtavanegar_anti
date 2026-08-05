<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$s = $settings;
?>
<div class="mvn-card">
	<h2>سخت‌سازی امنیتی</h2>
	<p>تنظیمات پایه برای کاهش سطح حمله. تغییرات بلافاصله اعمال می‌شوند.</p>

	<form id="mvn-hardening-form">
		<table class="form-table mvn-form-table">
			<tr>
				<th>مسدودسازی XML-RPC</th>
				<td>
					<label><input type="checkbox" name="settings[block_xmlrpc]" value="1" <?php checked( ! empty( $s['block_xmlrpc'] ) ); ?>>
					مسدود کردن <code>xmlrpc.php</code> (جلوگیری از brute-force و حملات pingback)</label>
				</td>
			</tr>
			<tr>
				<th>محافظت Brute Force ورود</th>
				<td>
					<label><input type="checkbox" name="settings[login_brute_force]" value="1" <?php checked( ! empty( $s['login_brute_force'] ) ); ?>>
					قفل موقت IP بعد از تلاش‌های ناموفق</label>
					<div class="mvn-inline-fields">
						<label>حداکثر تلاش
							<input type="number" min="2" max="50" name="settings[login_max_attempts]" value="<?php echo (int) $s['login_max_attempts']; ?>" class="small-text">
						</label>
						<label>مدت قفل (دقیقه)
							<input type="number" min="5" max="1440" name="settings[login_lockout_minutes]" value="<?php echo (int) $s['login_lockout_minutes']; ?>" class="small-text">
						</label>
					</div>
				</td>
			</tr>
			<tr>
				<th>غیرفعال‌سازی ویرایشگر فایل</th>
				<td>
					<label><input type="checkbox" name="settings[disable_file_edit]" value="1" <?php checked( ! empty( $s['disable_file_edit'] ) ); ?>>
					<code>DISALLOW_FILE_EDIT</code> — حذف ویرایشگر پوسته/افزونه از پیشخوان</label>
				</td>
			</tr>
			<tr>
				<th>غیرفعال‌سازی نصب/آپدیت فایل</th>
				<td>
					<label><input type="checkbox" name="settings[disable_file_mods]" value="1" <?php checked( ! empty( $s['disable_file_mods'] ) ); ?>>
					<code>DISALLOW_FILE_MODS</code> — نصب و به‌روزرسانی پلاگین/قالب از پیشخوان غیرفعال شود (سخت‌گیرانه)</label>
				</td>
			</tr>
			<tr>
				<th>مخفی‌سازی نسخه وردپرس</th>
				<td>
					<label><input type="checkbox" name="settings[hide_wp_version]" value="1" <?php checked( ! empty( $s['hide_wp_version'] ) ); ?>>
					حذف generator و متا نسخه</label>
				</td>
			</tr>
			<tr>
				<th>جلوگیری از User Enumeration</th>
				<td>
					<label><input type="checkbox" name="settings[block_user_enum]" value="1" <?php checked( ! empty( $s['block_user_enum'] ) ); ?>>
					مسدود کردن <code>?author=1</code> و endpoint کاربران REST API</label>
				</td>
			</tr>
			<tr>
				<th>Application Passwords</th>
				<td>
					<label><input type="checkbox" name="settings[disable_app_passwords]" value="1" <?php checked( ! empty( $s['disable_app_passwords'] ) ); ?>>
					غیرفعال‌سازی Application Passwords</label>
				</td>
			</tr>
			<tr>
				<th>پاکسازی لینک‌های اضافی</th>
				<td>
					<label><input type="checkbox" name="settings[remove_really_simple]" value="1" <?php checked( ! empty( $s['remove_really_simple'] ) ); ?>>
					حذف RSD / wlwmanifest / shortlink / REST link از head</label>
				</td>
			</tr>
			<tr>
				<th>هدرهای امنیتی</th>
				<td>
					<label><input type="checkbox" name="settings[secure_headers]" value="1" <?php checked( ! empty( $s['secure_headers'] ) ); ?>>
					ارسال X-Content-Type-Options، X-Frame-Options، Referrer-Policy</label>
				</td>
			</tr>
		</table>

		<p>
			<button type="submit" class="button button-primary button-hero">ذخیره تنظیمات</button>
			<span id="mvn-hardening-result" style="margin-right:12px"></span>
		</p>
	</form>
</div>
