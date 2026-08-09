<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<?php
$ghost = isset( $ghost ) && is_array( $ghost ) ? $ghost : array(
	'ioc_paths'          => array(),
	'persistence'        => array(),
	'protections'        => array(),
	'hidden_plugins'     => array(),
	'ghost_admins'       => 0,
	'ghost_admin_sample' => array(),
	'tracker_options'    => array(),
	'sql_admins'         => 0,
	'visible_admins'     => 0,
);
?>
<div class="mvn-card" style="margin-bottom:16px">
	<h2>Rollback تراکنشی</h2>
	<p class="mvn-muted">بازگردانی عملیات اخیر نیازمند تأیید دوم مرورگر است.</p>
	<?php if ( ! empty( $cstate['backups'] ) ) : ?><button class="button mvn-repair-rollback" data-action="mvn_core_rollback">Rollback هسته</button><?php endif; ?>
	<?php if ( ! empty( $plstate['rollback_path'] ) ) : ?><button class="button mvn-repair-rollback" data-action="mvn_plugin_rollback">Rollback پلاگین</button><?php endif; ?>
	<?php if ( ! empty( $thstate['rollback_path'] ) ) : ?><button class="button mvn-repair-rollback" data-action="mvn_theme_rollback">Rollback قالب</button><?php endif; ?>
	<button class="button mvn-repair-rollback" data-action="mvn_immutable_release">Release قفل‌های immutable ثبت‌شده</button>
	<div id="mvn-rollback-result"></div>
</div>
<div class="mvn-card" style="margin-bottom:16px">
	<h2>پاک‌سازی پایدار: xdav-tracker / Zonal Runner Tap</h2>
	<p>
		این‌ها پلاگین‌های جعلی با نام بازاریابی ساختگی‌اند. معمولاً خود را از لیست Plugins مخفی می‌کنند،
		ادمین مخفی می‌سازند، و از <code>mu-plugins</code> یا <code>wp-content/upgrade/</code> دوباره نصب می‌شوند.
		ترتیب: <strong>فایل + دراپر</strong> → <strong>DB</strong> → <strong>تعمیر هسته</strong> → <strong>پسورد/FTP</strong>.
	</p>
	<ul class="mvn-kv">
		<li>
			<span>IoC روی دیسک</span>
			<b class="<?php echo empty( $ghost['ioc_paths'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
				<?php echo empty( $ghost['ioc_paths'] ) ? 'یافت نشد' : esc_html( implode( '، ', $ghost['ioc_paths'] ) ); ?>
			</b>
		</li>
		<li>
			<span>لایه persistence</span>
			<b class="<?php echo empty( $ghost['persistence'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
				<?php echo empty( $ghost['persistence'] ) ? 'یافت نشد' : esc_html( implode( '، ', $ghost['persistence'] ) ); ?>
			</b>
		</li>
		<li>
			<span>محافظت موقت MVN</span>
			<b class="mvn-ok">
				<?php echo empty( $ghost['protections'] ) ? '—' : esc_html( implode( '، ', $ghost['protections'] ) ); ?>
			</b>
		</li>
		<li>
			<span>پلاگین مخفی (all_plugins)</span>
			<b class="<?php echo empty( $ghost['hidden_plugins'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
				<?php echo empty( $ghost['hidden_plugins'] ) ? '۰' : esc_html( implode( '، ', $ghost['hidden_plugins'] ) ); ?>
			</b>
		</li>
		<li>
			<span>ادمین ghost</span>
			<b class="<?php echo empty( $ghost['ghost_admins'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
				<?php
				echo (int) $ghost['ghost_admins'];
				if ( ! empty( $ghost['sql_admins'] ) || ! empty( $ghost['visible_admins'] ) ) {
					echo ' <span class="mvn-muted">(SQL: ' . (int) $ghost['sql_admins'] . ' / UI: ' . (int) $ghost['visible_admins'] . ')</span>';
				}
				if ( ! empty( $ghost['ghost_admin_sample'] ) ) {
					echo ' — نمونه: ' . esc_html( implode( '، ', $ghost['ghost_admin_sample'] ) );
				}
				?>
			</b>
		</li>
		<li>
			<span>option ردیابی</span>
			<b class="<?php echo empty( $ghost['tracker_options'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
				<?php echo empty( $ghost['tracker_options'] ) ? 'یافت نشد' : esc_html( implode( '، ', $ghost['tracker_options'] ) ); ?>
			</b>
		</li>
	</ul>
	<ol style="margin:12px 0 12px 1.4em;line-height:1.7">
		<li>دکمه زیر (۱.۸.۳): <strong>شکستن زنجیره auto_prepend</strong> (<code>.user.ini</code>→shell) با خنثی‌سازی + قفل، شکار <strong>dropper</strong> در کل <code>wp-content</code>، حذف cron مخرب، خنثی‌سازی <code>db.php</code>/<code>advanced-cache</code>/<code>object-cache</code>، چند پاس + shutdown، نصب db/MU امن.</li>
		<li>اگر File Manager حذف نکرد: تیک «Move to Trash» را <strong>بردارید</strong>؛ اول محتوای داخل پوشه را پاک کنید.</li>
		<li>بعد از دکمه: یک‌بار فرانت سایت را باز کنید، سپس این صفحه را رفرش کنید — وضعیت تمیز فقط بعد از رفرش معتبر است.</li>
		<li>اسکن کامل + حذف ادمین ghost از phpMyAdmin + تعمیر هسته + عوض کردن همه پسوردها/FTP/DB.</li>
	</ol>
	<button type="button" class="button button-primary" id="mvn-ghost-purge">
		حذف فوری persistence + IoC + شکستن زنجیره auto_prepend
	</button>
	<div id="mvn-ghost-purge-result" style="margin-top:10px"></div>
	<div class="mvn-card" style="margin-top:12px;background:#fff8e5;border:1px solid #f0c36d">
		<h3 style="margin-top:0">اگر باز هم برگشت: چرا و راه قطعی</h3>
		<p style="line-height:1.8">
			این خانواده یک <strong>پوستهٔ auto_prepend</strong> دارد که <em>قبل از</em> وردپرس روی هر درخواست اجرا می‌شود و همه‌چیز
			(<code>db.php</code>، <code>zonal-runner-tap.php</code>، فایل‌های hex، <code>.user.ini</code>) را دوباره می‌سازد.
			چون این کد <strong>قبل از پلاگین ما</strong> اجرا می‌شود، حذف صرف از داخل وردپرس همیشه یک قدم عقب است.
			به همین دلیل PHP فایل <code>.user.ini</code> را تا حدود ۵ دقیقه (<code>user_ini.cache_ttl</code>) کش می‌کند.
		</p>
		<p style="line-height:1.8">
			<strong>راه قطعی (به‌ترتیب):</strong>
		</p>
		<ol style="margin:6px 0 6px 1.4em;line-height:1.9">
			<li><strong>ابزار اضطراری مستقل</strong>: فایل <code>sources/mvn-emergency-clean.php</code> از همین پلاگین را بردارید،
				داخلش <code>MVN_TOKEN</code> را به یک رمز بلند تغییر دهید و کنار <code>wp-config.php</code> آپلود کنید.
				فقط با <code>POST</code> و هدر <code>Authorization: Bearer TOKEN</code> چند بار اجرا کنید؛ token هرگز در URL نباشد. سپس <code>action=self_delete</code> را POST کنید.</li>
			<li><strong>SSH (قطعی‌ترین)</strong>:
				<code>chattr -i .user.ini *.php wp-content/db.php wp-content/mu-plugins/*.php</code> سپس
				<code>rm -f</code> فایل‌های آلوده، و از هاست بخواهید <strong>PHP-FPM ری‌استارت</strong> شود تا کش <code>.user.ini</code> پاک شود.</li>
			<li>حذف ادمین‌های ghost از phpMyAdmin، تعمیر هسته، و <strong>تعویض همهٔ رمزها/FTP/DB/سکرت‌کی‌ها</strong>.
				تا وقتی راه ورود (FTP/رمز لو رفته) باز باشد، دوباره آلوده می‌شود.</li>
		</ol>
		<p class="mvn-muted">
			«محافظت موقت MVN» قرمز نیست؛ یعنی <code>db.php</code>/MU امن ما فعال است و روی هر درخواست reinfection را می‌کشد.
			ولی این فقط تا وقتی کار می‌کند که پوستهٔ prepend خنثی/قفل شده باشد.
		</p>
	</div>
</div>

<div class="mvn-grid mvn-grid-2">
	<div class="mvn-card">
		<h2>بررسی یکپارچگی هسته (Core Checksum)</h2>
		<p>
			فایل‌های <code>wp-admin</code>، <code>wp-includes</code> و فایل‌های ریشه هسته با
			<strong>MD5 رسمی wordpress.org</strong> مقایسه می‌شوند.
			فایل‌های <em>تغییر یافته</em>، <em>گم‌شده</em> یا <em>اضافی</em> گزارش می‌شوند.
		</p>
		<?php if ( ! empty( $integrity ) ) : ?>
		<ul class="mvn-kv">
			<li>
				<span>آخرین بررسی</span>
				<b class="<?php echo ! empty( $integrity['ok'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( ! empty( $integrity['ok'] ) ) {
						echo 'سالم';
					} else {
						echo (int) ( isset( $integrity['total'] ) ? $integrity['total'] : 0 ) . ' مشکل';
					}
					?>
				</b>
			</li>
			<?php if ( empty( $integrity['ok'] ) ) : ?>
			<li><span>تغییر یافته</span><b><?php echo (int) ( isset( $integrity['modified'] ) ? $integrity['modified'] : 0 ); ?></b></li>
			<li><span>گم‌شده</span><b><?php echo (int) ( isset( $integrity['missing'] ) ? $integrity['missing'] : 0 ); ?></b></li>
			<li><span>اضافی</span><b><?php echo (int) ( isset( $integrity['extra'] ) ? $integrity['extra'] : 0 ); ?></b></li>
			<?php endif; ?>
			<li><span>منبع checksum</span><b><?php echo esc_html( isset( $integrity['source'] ) ? $integrity['source'] : '—' ); ?></b></li>
		</ul>
		<?php endif; ?>
		<button type="button" class="button button-primary" id="mvn-integrity-start">شروع بررسی checksum</button>
		<div id="mvn-integrity-progress" class="mvn-progress-wrap" style="display:none;margin-top:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-integrity-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta">
				<span id="mvn-integrity-label">...</span>
				<span id="mvn-integrity-pct">0%</span>
			</div>
		</div>
		<div id="mvn-integrity-result" style="margin-top:12px"></div>
	</div>

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
				<b id="mvn-core-zip-status" class="<?php echo ! empty( $core['zip_ok'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( empty( $core['exists'] ) ) {
						echo 'فایل zip موجود نیست';
					} elseif ( empty( $core['zip_ok'] ) ) {
						echo 'آرشیو باز نمی‌شود';
					} else {
						$label = 'آماده — ' . (int) $core['files'] . ' ورودی / ' . esc_html( mvn_size_format( $core['size'] ) );
						if ( ! empty( $core['version'] ) ) {
							$label .= ' / نسخه ' . esc_html( $core['version'] );
						}
						echo $label;
					}
					?>
				</b>
			</li>
			<?php if ( ! empty( $core['downloaded_at'] ) ) : ?>
			<li>
				<span>آخرین دریافت از wordpress.org</span>
				<b id="mvn-core-zip-fetched"><?php
					$ts = strtotime( $core['downloaded_at'] );
					echo esc_html( $ts ? gmdate( 'Y/m/d H:i', $ts ) . ' UTC' : $core['downloaded_at'] );
				?></b>
			</li>
			<?php else : ?>
			<li>
				<span>آخرین دریافت از wordpress.org</span>
				<b id="mvn-core-zip-fetched" class="mvn-muted">هنوز دریافت نشده (نسخه همراه پلاگین)</b>
			</li>
			<?php endif; ?>
		</ul>
		<div class="mvn-actions" style="margin-top:12px">
			<button type="button" class="button" id="mvn-core-download" <?php disabled( empty( $core['writable'] ) ); ?>>
				دریافت آخرین نسخه وردپرس
			</button>
			<button type="button" class="button" id="mvn-core-selective" <?php disabled( empty( $core['zip_ok'] ) ); ?>>
				تعمیر انتخابی (فقط آسیب‌دیده‌ها)
			</button>
			<button type="button" class="button button-primary button-hero" id="mvn-core-start" <?php disabled( empty( $core['zip_ok'] ) ); ?>>
				شروع جایگزینی کامل هسته
			</button>
		</div>
		<p class="mvn-muted" style="margin-top:8px">
			«تعمیر انتخابی» فقط فایل‌های تغییر یافته/گم‌شدهٔ گزارش‌شده در آخرین اسکن را از zip بازمی‌گرداند.
			جایگزینی کامل همهٔ هسته را بازنویسی می‌کند.
		</p>
		<div id="mvn-core-download-result" style="margin-top:10px"></div>
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

	<div class="mvn-card">
		<h2>قفل PHP در uploads</h2>
		<p>
			یک <code>.htaccess</code> امن داخل <code>wp-content/uploads</code> می‌نویسد تا اجرای
			<code>.php / .phtml / .phar</code> در پوشه آپلود غیرفعال شود (جلوگیری از webshell).
		</p>
		<?php
		$uploads_ht = isset( $uploads_ht ) && is_array( $uploads_ht ) ? $uploads_ht : array();
		?>
		<ul class="mvn-kv">
			<li>
				<span>وضعیت</span>
				<b id="mvn-uploads-ht-status" class="<?php echo ! empty( $uploads_ht['hardened'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( empty( $uploads_ht['exists'] ) ) {
						echo 'htaccess ندارد';
					} elseif ( ! empty( $uploads_ht['hardened'] ) ) {
						echo 'محافظت فعال (deny PHP)';
					} else {
						echo 'وجود دارد ولی محافظت کامل نیست';
					}
					?>
				</b>
			</li>
		</ul>
		<button type="button" class="button button-primary" id="mvn-uploads-harden">اعمال deny-PHP روی uploads</button>
		<div id="mvn-uploads-harden-result" style="margin-top:10px"></div>
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

<div class="mvn-card" style="margin-top:16px">
	<h2>تعمیر پلاگین‌های مخزن وردپرس</h2>
	<p>
		اگر فایل‌های پلاگین‌های رایگان مخزن وردپرس (مثل Elementor، ویرایشگر کلاسیک، LiteSpeed Cache) آلوده شده باشند،
		نسخه سالم از <code>wordpress.org</code> دانلود و جایگزین می‌شود.
		قبل از جایگزینی، نسخه فعلی در data-dir امن پشتیبان‌گیری می‌شود.
	</p>

	<div id="mvn-plugin-progress" class="mvn-progress-wrap" style="display:none;margin-bottom:16px">
		<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-plugin-bar" style="width:0%"></div></div>
		<div class="mvn-progress-meta">
			<span id="mvn-plugin-label">...</span>
			<span id="mvn-plugin-pct">0%</span>
		</div>
	</div>
	<div id="mvn-plugin-result" style="margin-bottom:16px"></div>

	<table class="widefat striped mvn-table" id="mvn-plugins-table">
		<thead>
			<tr>
				<th>پلاگین</th>
				<th>slug</th>
				<th>وضعیت</th>
				<th>نسخه</th>
				<th>فایل‌ها</th>
				<th></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $plugins as $pl ) : ?>
			<tr data-slug="<?php echo esc_attr( $pl['slug'] ); ?>">
				<td><strong><?php echo esc_html( $pl['name'] ); ?></strong></td>
				<td><code><?php echo esc_html( $pl['slug'] ); ?></code></td>
				<td>
					<?php if ( ! empty( $pl['protected'] ) ) : ?>
						<span class="mvn-badge mvn-badge-info">محافظت‌شده</span>
					<?php elseif ( ! empty( $pl['installed'] ) ) : ?>
						<span class="mvn-badge mvn-badge-<?php echo ! empty( $pl['active'] ) ? 'warning' : 'info'; ?>">
							<?php echo ! empty( $pl['active'] ) ? 'نصب + فعال' : 'نصب‌شده'; ?>
						</span>
					<?php else : ?>
						<span class="mvn-muted">نصب نشده</span>
					<?php endif; ?>
				</td>
				<td><?php echo $pl['version'] ? esc_html( $pl['version'] ) : '—'; ?></td>
				<td><?php echo ! empty( $pl['installed'] ) ? (int) $pl['file_count'] : '—'; ?></td>
				<td>
					<?php if ( empty( $pl['protected'] ) ) : ?>
						<button type="button" class="button button-small button-primary mvn-plugin-repair"
							data-slug="<?php echo esc_attr( $pl['slug'] ); ?>"
							data-name="<?php echo esc_attr( $pl['name'] ); ?>">
							<?php echo ! empty( $pl['installed'] ) ? 'جایگزینی از مخزن' : 'نصب از مخزن'; ?>
						</button>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>

	<p class="mvn-muted">
		توجه: فقط پلاگین‌های رایگان wordpress.org پشتیبانی می‌شوند. پلاگین‌های پریمیوم یا خارج از مخزن باید دستی جایگزین شوند.
		برای افزودن پلاگین به لیست از فیلتر <code>mvn_repo_plugins</code> در functions.php استفاده کنید.
	</p>
</div>

<div class="mvn-card" style="margin-top:16px">
	<h2>تعمیر قالب‌های مخزن وردپرس</h2>
	<p>
		قالب‌های نصب‌شده را از <code>themes.wordpress.org</code> دوباره می‌گیرد و جایگزین می‌کند.
		قبل از جایگزینی، نسخه فعلی در data-dir امن پشتیبان می‌شود.
		قالب‌های پریمیوم/خارج از مخزن قابل دانلود نیستند.
	</p>

	<div id="mvn-theme-progress" class="mvn-progress-wrap" style="display:none;margin-bottom:16px">
		<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-theme-bar" style="width:0%"></div></div>
		<div class="mvn-progress-meta">
			<span id="mvn-theme-label">...</span>
			<span id="mvn-theme-pct">0%</span>
		</div>
	</div>
	<div id="mvn-theme-result" style="margin-bottom:16px"></div>

	<table class="widefat striped mvn-table" id="mvn-themes-table">
		<thead>
			<tr>
				<th>قالب</th>
				<th>slug</th>
				<th>وضعیت</th>
				<th>نسخه</th>
				<th>فایل‌ها</th>
				<th></th>
			</tr>
		</thead>
		<tbody>
		<?php
		$themes = isset( $themes ) && is_array( $themes ) ? $themes : array();
		foreach ( $themes as $th ) :
			?>
			<tr data-slug="<?php echo esc_attr( $th['slug'] ); ?>">
				<td><strong><?php echo esc_html( $th['name'] ); ?></strong></td>
				<td><code><?php echo esc_html( $th['slug'] ); ?></code></td>
				<td>
					<?php if ( ! empty( $th['active'] ) ) : ?>
						<span class="mvn-badge mvn-badge-warning">فعال</span>
					<?php else : ?>
						<span class="mvn-badge mvn-badge-info">نصب‌شده</span>
					<?php endif; ?>
				</td>
				<td><?php echo $th['version'] ? esc_html( $th['version'] ) : '—'; ?></td>
				<td><?php echo (int) $th['file_count']; ?></td>
				<td>
					<button type="button" class="button button-small button-primary mvn-theme-repair"
						data-slug="<?php echo esc_attr( $th['slug'] ); ?>"
						data-name="<?php echo esc_attr( $th['name'] ); ?>">
						جایگزینی از مخزن
					</button>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>
