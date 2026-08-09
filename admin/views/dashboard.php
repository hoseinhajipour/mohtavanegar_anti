<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$issue_count = is_array( $issues ) ? count( $issues ) : 0;
$crit = 0;
$warn = 0;
if ( is_array( $issues ) ) {
	foreach ( $issues as $iss ) {
		if ( isset( $iss['severity'] ) && 'critical' === $iss['severity'] ) {
			$crit++;
		} else {
			$warn++;
		}
	}
}
$checklist = isset( $checklist ) && is_array( $checklist ) ? $checklist : array( 'items' => array(), 'done' => 0, 'total' => 0, 'pct' => 0 );
$cl_pct    = (int) $checklist['pct'];
$cl_done   = (int) $checklist['done'];
$cl_total  = (int) $checklist['total'];
$cl_pending = max( 0, $cl_total - $cl_done );
$ring_r    = 54;
$ring_c    = 2 * M_PI * $ring_r;
$ring_off  = $ring_c * ( 1 - ( $cl_pct / 100 ) );
$incidents = isset( $incidents ) && is_array( $incidents ) ? $incidents : array();
$open_incidents = array_filter( $incidents, static function ( $row ) { return isset( $row['status'] ) && in_array( $row['status'], array( 'open', 'failed' ), true ); } );
$verified_incidents = array_filter( $incidents, static function ( $row ) { return isset( $row['status'] ) && 'verified' === $row['status']; } );
$last_verified = $verified_incidents ? end( $verified_incidents ) : array();
$sig_age = ! empty( $sig_pack['updated_at'] ) ? human_time_diff( strtotime( $sig_pack['updated_at'] ), time() ) : 'نامشخص';
$data_outside = ! mvn_path_is_within( $data_dir, ABSPATH );
?>
<div class="mvn-card">
	<h2>سلامت موتور امنیت 2.0</h2>
	<ul class="mvn-kv">
		<li><span>سن بسته امضا</span><b><?php echo esc_html( $sig_age ); ?></b></li>
		<li><span>Self-integrity افزونه</span><b class="<?php echo ! empty( $self_integrity['ok'] ) ? 'mvn-ok' : 'mvn-bad'; ?>"><?php echo ! empty( $self_integrity['ok'] ) ? 'تأییدشده' : 'تغییر/کمبود فایل'; ?></b></li>
		<li><span>اسکن پس‌زمینه</span><b class="<?php echo ! empty( $schedule['enabled'] ) ? 'mvn-warn' : 'mvn-ok'; ?>"><?php echo ! empty( $schedule['enabled'] ) ? 'روشن' : 'خاموش (سریع‌تر)'; ?></b></li>
		<li><span>WP-Cron</span><b class="<?php echo empty( $schedule['cron_disabled'] ) ? 'mvn-ok' : 'mvn-warn'; ?>"><?php echo empty( $schedule['cron_disabled'] ) ? 'فعال' : 'غیرفعال؛ system cron لازم است'; ?></b></li>
		<li><span>data-dir</span><b class="<?php echo $data_outside ? 'mvn-ok' : 'mvn-warn'; ?>"><?php echo $data_outside ? 'خارج webroot سایت' : 'fallback داخل webroot (payload رمزنگاری می‌شود)'; ?></b></li>
		<li><span>رخدادهای باز/failed</span><b class="<?php echo $open_incidents ? 'mvn-bad' : 'mvn-ok'; ?>"><?php echo count( $open_incidents ); ?></b></li>
		<li><span>آخرین پاک‌سازی verified</span><b><?php echo esc_html( ! empty( $last_verified['updated_at'] ) ? $last_verified['updated_at'] : '—' ); ?></b></li>
		<li><span>Outbound anomaly</span><b><?php echo esc_html( ! empty( $audit_rows ) ? 'audit فعال' : 'موردی ثبت نشده' ); ?></b></li>
		<li><span>مسیرهای Watched</span><b><?php echo (int) ( class_exists( 'MVN_Reinfection_Monitor' ) ? count( MVN_Reinfection_Monitor::watched() ) : 0 ); ?></b></li>
		<li><span>Security log</span><b><a href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-cron' ) ); ?>">Cron / Logs</a></b></li>
	</ul>
	<?php if ( ! empty( $schedule['cron_disabled'] ) ) : ?><code><?php echo esc_html( $schedule['system_cron'] ); ?></code><?php endif; ?>
</div>
<div class="mvn-card mvn-checklist-hero">
	<div class="mvn-checklist-hero-inner">
		<div class="mvn-checklist-ring-wrap" aria-hidden="true">
			<svg class="mvn-checklist-ring" viewBox="0 0 120 120" width="120" height="120">
				<circle class="mvn-ring-bg" cx="60" cy="60" r="<?php echo (float) $ring_r; ?>"></circle>
				<circle
					class="mvn-ring-fg <?php echo $cl_pct >= 100 ? 'is-complete' : ( $cl_pct < 50 ? 'is-low' : 'is-mid' ); ?>"
					cx="60" cy="60" r="<?php echo (float) $ring_r; ?>"
					stroke-dasharray="<?php echo esc_attr( (string) round( $ring_c, 2 ) ); ?>"
					stroke-dashoffset="<?php echo esc_attr( (string) round( $ring_off, 2 ) ); ?>"
				></circle>
			</svg>
			<div class="mvn-checklist-ring-label">
				<strong><?php echo (int) $cl_pct; ?>%</strong>
				<span>ایمن‌سازی</span>
			</div>
		</div>
		<div class="mvn-checklist-hero-text">
			<h2>چک‌لیست کارهای امنیتی</h2>
			<p>
				<strong class="mvn-ok"><?php echo (int) $cl_done; ?></strong> انجام‌شده
				·
				<strong class="<?php echo $cl_pending > 0 ? 'mvn-bad' : 'mvn-ok'; ?>"><?php echo (int) $cl_pending; ?></strong> باقی‌مانده
				از <?php echo (int) $cl_total; ?> مورد
			</p>
			<p class="mvn-muted">موارد قرمز هنوز انجام نشده‌اند؛ با لینک هر مورد به صفحه مربوطه بروید.</p>
		</div>
	</div>

	<div class="mvn-checklist-bar">
		<div class="mvn-checklist-bar-fill <?php echo $cl_pct >= 100 ? 'is-complete' : ( $cl_pct < 50 ? 'is-low' : 'is-mid' ); ?>" style="width:<?php echo (int) $cl_pct; ?>%"></div>
	</div>

	<ul class="mvn-checklist">
		<?php foreach ( $checklist['items'] as $item ) : ?>
			<?php
			$done = ! empty( $item['done'] );
			?>
			<li class="mvn-checklist-item <?php echo $done ? 'is-done' : 'is-pending'; ?>">
				<span class="mvn-checklist-icon" aria-hidden="true"><?php echo $done ? '✓' : '!'; ?></span>
				<div class="mvn-checklist-body">
					<div class="mvn-checklist-title"><?php echo esc_html( isset( $item['title'] ) ? $item['title'] : '' ); ?></div>
					<div class="mvn-checklist-desc"><?php echo esc_html( isset( $item['desc'] ) ? $item['desc'] : '' ); ?></div>
				</div>
				<?php if ( ! empty( $item['url'] ) ) : ?>
					<a class="button <?php echo $done ? '' : 'button-primary'; ?> mvn-checklist-btn" href="<?php echo esc_url( $item['url'] ); ?>">
						<?php echo esc_html( $done ? 'مشاهده' : ( isset( $item['action'] ) ? $item['action'] : 'انجام' ) ); ?>
					</a>
				<?php endif; ?>
			</li>
		<?php endforeach; ?>
	</ul>
</div>

<div class="mvn-grid mvn-grid-4" style="margin-top:16px">
	<div class="mvn-card mvn-stat <?php echo $crit > 0 ? 'is-danger' : 'is-ok'; ?>">
		<div class="mvn-stat-num"><?php echo (int) $crit; ?></div>
		<div class="mvn-stat-label">تهدید بحرانی</div>
	</div>
	<div class="mvn-card mvn-stat <?php echo $warn > 0 ? 'is-warn' : 'is-ok'; ?>">
		<div class="mvn-stat-num"><?php echo (int) $warn; ?></div>
		<div class="mvn-stat-label">هشدار</div>
	</div>
	<div class="mvn-card mvn-stat">
		<div class="mvn-stat-num"><?php echo (int) $q_count; ?></div>
		<div class="mvn-stat-label">آیتم قرنطینه</div>
	</div>
	<div class="mvn-card mvn-stat <?php echo ! empty( $ht['matches'] ) ? 'is-ok' : 'is-warn'; ?>">
		<div class="mvn-stat-num"><?php echo ! empty( $ht['matches'] ) ? '✓' : '!'; ?></div>
		<div class="mvn-stat-label">وضعیت htaccess ریشه</div>
	</div>
</div>

<div class="mvn-grid mvn-grid-2" style="margin-top:16px">
	<div class="mvn-card">
		<h2>آخرین اسکن</h2>
		<?php if ( empty( $last ) ) : ?>
			<p class="mvn-muted">هنوز اسکنی انجام نشده. از منوی «اسکن» شروع کنید.</p>
			<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-scan' ) ); ?>">شروع اسکن</a>
		<?php else : ?>
			<ul class="mvn-kv">
				<li><span>شناسه</span><b><?php echo esc_html( isset( $last['id'] ) ? $last['id'] : '—' ); ?></b></li>
				<li><span>شروع</span><b><?php echo esc_html( isset( $last['started_at'] ) ? $last['started_at'] : '—' ); ?></b></li>
				<li><span>پایان</span><b><?php echo esc_html( isset( $last['finished_at'] ) ? $last['finished_at'] : '—' ); ?></b></li>
				<li><span>فایل‌های بررسی‌شده</span><b><?php echo isset( $last['total'] ) ? (int) $last['total'] : 0; ?></b></li>
				<?php if ( ! empty( $last['catalog'] ) ) : ?>
				<li><span>کل فایل‌های کاتالوگ</span><b><?php echo (int) $last['catalog']; ?></b></li>
				<?php endif; ?>
				<?php if ( ! empty( $last['skipped_unchanged'] ) ) : ?>
				<li><span>ردشده (بدون تغییر)</span><b class="mvn-ok"><?php echo (int) $last['skipped_unchanged']; ?></b></li>
				<?php endif; ?>
				<?php if ( ! empty( $last['scan_core'] ) ) : ?>
				<li><span>checksum هسته</span><b class="mvn-ok">فعال</b></li>
				<?php endif; ?>
				<?php if ( isset( $last['incremental'] ) ) : ?>
				<li><span>نوع اسکن فایل</span><b><?php echo ! empty( $last['incremental'] ) ? 'افزایشی' : 'کامل'; ?></b></li>
				<?php endif; ?>
				<?php if ( ! empty( $last['scan_db'] ) ) : ?>
				<li><span>اسکن DB</span><b class="mvn-ok">فعال<?php echo ! empty( $last['db_total'] ) ? ' (' . (int) $last['db_total'] . ' ردیف)' : ''; ?></b></li>
				<?php endif; ?>
				<?php if ( ! empty( $last['scan_as'] ) ) : ?>
				<li><span>اسکن Action Scheduler</span><b class="mvn-ok">فعال</b></li>
				<?php endif; ?>
				<li><span>مشکلات باز</span><b><?php echo (int) $issue_count; ?></b></li>
			</ul>
			<?php if ( $issue_count > 0 ) : ?>
				<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-fix' ) ); ?>">رفتن به رفع مشکلات (<?php echo (int) $issue_count; ?>)</a>
			<?php endif; ?>
		<?php endif; ?>
	</div>

	<div class="mvn-card">
		<h2>وضعیت منابع تعمیر</h2>
		<ul class="mvn-kv">
			<li>
				<span>بسته امضا</span>
				<b class="mvn-ok">
					<?php
					$sp = isset( $sig_pack ) && is_array( $sig_pack ) ? $sig_pack : array();
					echo 'v' . esc_html( isset( $sp['version'] ) ? $sp['version'] : '?' );
					echo ' — ' . (int) ( isset( $sp['sig_count'] ) ? $sp['sig_count'] : 0 ) . ' امضا اضافه';
					?>
				</b>
			</li>
			<li>
				<span>wordpress_core.zip</span>
				<b class="<?php echo ! empty( $core['zip_ok'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( empty( $core['exists'] ) ) {
						echo 'یافت نشد';
					} elseif ( empty( $core['zip_ok'] ) ) {
						echo 'نامعتبر';
					} else {
						echo 'سالم (' . (int) $core['files'] . ' فایل / ' . esc_html( mvn_size_format( $core['size'] ) ) . ')';
					}
					?>
				</b>
			</li>
			<li>
				<span>default.htaccess</span>
				<b class="<?php echo ! empty( $ht['source_ok'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php echo ! empty( $ht['source_ok'] ) ? 'موجود' : 'یافت نشد'; ?>
				</b>
			</li>
			<li>
				<span>htaccess فعلی سایت</span>
				<b class="<?php echo ! empty( $ht['matches'] ) ? 'mvn-ok' : 'mvn-bad'; ?>">
					<?php
					if ( empty( $ht['exists'] ) ) {
						echo 'وجود ندارد';
					} elseif ( ! empty( $ht['matches'] ) ) {
						echo 'مطابق پیش‌فرض پلاگین';
					} else {
						echo 'متفاوت از پیش‌فرض — پیشنهاد بازیابی';
					}
					?>
				</b>
			</li>
		</ul>
		<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-repair' ) ); ?>">صفحه تعمیر هسته</a>
	</div>
</div>

<div class="mvn-card" style="margin-top:16px">
	<h2>اقدامات سریع</h2>
	<div class="mvn-actions">
		<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-scan' ) ); ?>">اسکن کامل سایت</a>
		<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-fix' ) ); ?>">حذف کدهای تزریق‌شده / htaccess جعلی</a>
		<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-repair' ) ); ?>">جایگزینی فایل‌های هسته وردپرس</a>
		<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-hardening' ) ); ?>">فعال‌سازی محافظت Brute Force و XML-RPC</a>
	</div>
	<p class="mvn-muted" style="margin-top:12px">
		پیشنهاد ترتیب کار بعد از آلودگی: <b>۱) اسکن</b> → <b>۲) رفع (حذف injection و htaccess جعلی)</b> → <b>۳) تعمیر هسته از zip</b> → <b>۴) بازیابی htaccess ریشه</b> → <b>۵) سطح دسترسی‌ها</b> → <b>۶) سخت‌سازی</b>.
	</p>
</div>
