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
			<tr>
				<th>عدم درج نظرات</th>
				<td>
					<label><input type="checkbox" name="settings[disable_comments]" value="1" <?php checked( ! empty( $s['disable_comments'] ) ); ?>>
					غیرفعال‌سازی نظرات و trackback در کل سایت (فرم، REST، پیشخوان و <code>wp-comments-post.php</code>)</label>
				</td>
			</tr>
			<tr>
				<th>مسدودسازی مسیرهای reinfection</th>
				<td>
					<label><input type="checkbox" name="path_blocker_enabled" value="1" <?php checked( ! class_exists( 'MVN_Path_Blocker' ) || MVN_Path_Blocker::is_enabled() ); ?>>
					جلوگیری از ساخت <code>wp-content/cache</code>، <code>wpo-cache</code> و <code>db.php</code></label>
					<p class="description" style="margin-top:6px">
						این مسیرها برای staging بدافزار استفاده می‌شوند. افزونه آن‌ها را حذف می‌کند و به‌جای پوشه، فایل بلاکر می‌گذارد تا <code>mkdir</code> شکست بخورد. کش صفحه‌ای WP-Optimize با این گزینه کار نمی‌کند.
					</p>
				</td>
			</tr>
			<tr>
				<th>اسکن پس‌زمینه خودکار</th>
				<td>
					<label><input type="checkbox" name="schedule_enabled" value="1" <?php checked( class_exists( 'MVN_Scheduler' ) && MVN_Scheduler::is_enabled() ); ?>>
					اجرای اسکن روزانه/هفتگی در پس‌زمینه (WP-Cron)</label>
					<p class="description" style="margin-top:6px">
						پیش‌فرض <strong>خاموش</strong> است تا سایت کند نشود. فقط وقتی سیستم cron سرور دارید روشن کنید؛ اسکن دستی از صفحه «اسکن» همیشه در دسترس است.
					</p>
				</td>
			</tr>
			<tr>
				<th>غیرفعال‌سازی WP-Cron</th>
				<td>
					<label><input type="checkbox" name="settings[disable_wp_cron]" value="1" <?php checked( ! empty( $s['disable_wp_cron'] ) ); ?>>
					<code>DISABLE_WP_CRON</code> — توقف cron وردپرس و مسدود کردن <code>wp-cron.php</code></label>
					<p class="description" style="margin-top:6px">
						اسپاون خودکار روی بازدیدها قطع می‌شود و دسترسی مستقیم به <code>wp-cron.php</code> هم مسدود است.
						برای سایت آلوده مفید است؛ بعد از پاکسازی اگر به زمان‌بندی نیاز دارید، خاموشش کنید یا از cron سیستمی روی سرور استفاده کنید.
					</p>
				</td>
			</tr>
			<tr>
				<th>مسدودسازی HTTP خارجی</th>
				<td>
					<label><input type="checkbox" name="settings[block_external_http]" value="1" <?php checked( ! empty( $s['block_external_http'] ) ); ?>>
					قطع همه درخواست‌های HTTP از سرور به دامنه‌های خارجی</label>
					<p class="description" style="margin-top:6px">سخت‌گیرانه است: آپدیت هسته/افزونه و سرویس‌های خارجی قطع می‌شوند. برای اجازه یا مسدود کردن دامنه‌های خاص، بخش «مدیریت درخواست‌های خروجی» پایین همین صفحه را ببینید.</p>
				</td>
			</tr>
			<tr>
				<th>عدم ثبت‌نام مدیر / نویسنده</th>
				<td>
					<label><input type="checkbox" name="settings[block_privileged_signup]" value="1" <?php checked( ! empty( $s['block_privileged_signup'] ) ); ?>>
					جلوگیری از ایجاد کاربر جدید با نقش <strong>مدیر</strong> یا <strong>نویسنده</strong></label>
					<p class="description" style="margin-top:6px">ثبت‌نام عمومی، «افزودن کاربر» در پیشخوان و REST را پوشش می‌دهد. کاربران فعلی دست‌نخورده می‌مانند؛ فقط کاربر تازه‌ساخته‌شده نمی‌تواند این نقش‌ها را بگیرد.</p>
				</td>
			</tr>
		</table>

		<p>
			<button type="submit" class="button button-primary button-hero">ذخیره تنظیمات</button>
			<span id="mvn-hardening-result" style="margin-right:12px"></span>
		</p>
	</form>
</div>

<?php
$hg           = isset( $http_guard ) && is_array( $http_guard ) ? $http_guard : array();
$hg_entries   = isset( $hg['entries'] ) && is_array( $hg['entries'] ) ? $hg['entries'] : array();
$hg_global    = ! empty( $hg['global_block'] );
$hg_blocked_n = isset( $hg['blocked_hosts'] ) && is_array( $hg['blocked_hosts'] ) ? count( $hg['blocked_hosts'] ) : 0;
$hg_allowed_n = isset( $hg['allowed_hosts'] ) && is_array( $hg['allowed_hosts'] ) ? count( $hg['allowed_hosts'] ) : 0;
?>
<div class="mvn-card" id="mvn-http-guard">
	<h2>مدیریت درخواست‌های خروجی (HTTP)</h2>
	<p>
		درخواست‌هایی که از داخل سرور به بیرون می‌روند اینجا ثبت می‌شوند.
		می‌توانید هر دامنه را جداگانه <strong>مسدود</strong> یا <strong>مجاز</strong> کنید.
		<?php if ( $hg_global ) : ?>
			<br><span class="mvn-badge mvn-badge-warning">مسدودسازی سراسری فعال است</span>
			<span class="mvn-muted">— همه دامنه‌های خارجی بسته هستند مگر آن‌هایی که آنبلاک کرده باشید.</span>
		<?php else : ?>
			<br><span class="mvn-muted">مسدودسازی سراسری خاموش است — فقط دامنه‌هایی که بلاک کرده باشید قطع می‌شوند.</span>
		<?php endif; ?>
	</p>

	<div class="mvn-actions" style="margin-bottom:14px;flex-wrap:wrap;gap:8px">
		<button type="button" class="button" id="mvn-http-refresh">بروزرسانی فهرست</button>
		<button type="button" class="button" id="mvn-http-clear">پاک کردن لاگ</button>
		<span class="mvn-muted" id="mvn-http-meta">
			<?php
			echo esc_html(
				sprintf(
					'%d دامنه ثبت‌شده · %d مسدود · %d مجاز (استثنا)',
					count( $hg_entries ),
					$hg_blocked_n,
					$hg_allowed_n
				)
			);
			?>
		</span>
		<span id="mvn-http-result" style="margin-right:8px"></span>
	</div>

	<div class="mvn-form-row" style="margin-bottom:16px">
		<label for="mvn-http-add-host">افزودن دامنه دستی</label>
		<input type="text" id="mvn-http-add-host" class="regular-text" placeholder="example.com" dir="ltr">
		<button type="button" class="button" id="mvn-http-add">افزودن</button>
		<button type="button" class="button" id="mvn-http-add-block">افزودن و مسدود</button>
	</div>

	<div id="mvn-http-empty" class="mvn-empty" <?php echo $hg_entries ? 'style="display:none"' : ''; ?>>
		هنوز درخواستی ثبت نشده. پس از فعالیت سایت (آپدیت، API افزونه‌ها و …) دامنه‌ها اینجا ظاهر می‌شوند.
	</div>

	<table class="widefat striped mvn-table" id="mvn-http-table" <?php echo $hg_entries ? '' : 'style="display:none"'; ?>>
		<thead>
			<tr>
				<th>دامنه</th>
				<th>وضعیت</th>
				<th>تعداد</th>
				<th>آخرین درخواست</th>
				<th>آخرین URL</th>
				<th></th>
			</tr>
		</thead>
		<tbody id="mvn-http-tbody">
			<?php foreach ( $hg_entries as $row ) : ?>
				<?php
				$host   = isset( $row['host'] ) ? (string) $row['host'] : '';
				$status = isset( $row['status'] ) ? (string) $row['status'] : 'allowed';
				?>
				<tr data-host="<?php echo esc_attr( $host ); ?>">
					<td dir="ltr"><code><?php echo esc_html( $host ); ?></code></td>
					<td>
						<?php if ( 'blocked' === $status ) : ?>
							<span class="mvn-badge mvn-badge-critical">مسدود</span>
						<?php elseif ( 'local' === $status ) : ?>
							<span class="mvn-badge mvn-badge-info">محلی</span>
						<?php else : ?>
							<span class="mvn-badge mvn-badge-info">مجاز</span>
						<?php endif; ?>
					</td>
					<td><?php echo (int) ( isset( $row['count'] ) ? $row['count'] : 0 ); ?></td>
					<td><?php echo esc_html( isset( $row['last_seen_human'] ) ? $row['last_seen_human'] : '' ); ?></td>
					<td class="mvn-path" dir="ltr"><code><?php echo esc_html( isset( $row['last_url'] ) ? $row['last_url'] : '' ); ?></code></td>
					<td class="mvn-actions-cell">
						<?php if ( 'blocked' === $status ) : ?>
							<button type="button" class="button button-small mvn-http-unblock" data-host="<?php echo esc_attr( $host ); ?>">آنبلاک</button>
						<?php elseif ( 'local' !== $status ) : ?>
							<button type="button" class="button button-small button-link-delete mvn-http-block" data-host="<?php echo esc_attr( $host ); ?>">بلاک</button>
						<?php else : ?>
							<span class="mvn-muted">—</span>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</div>
