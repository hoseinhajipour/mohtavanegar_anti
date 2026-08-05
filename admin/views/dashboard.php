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
?>
<div class="mvn-grid mvn-grid-4">
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
