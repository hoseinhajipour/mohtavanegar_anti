<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$arm     = isset( $arm ) && is_array( $arm ) ? $arm : array( 'active' => false );
$report  = isset( $report ) && is_array( $report ) ? $report : array();
$blocked = isset( $blocked ) && is_array( $blocked ) ? $blocked : array();
$has     = ! empty( $report['captured_at'] );
?>
<div class="mvn-card">
	<h2>رهگیری سرعت لود وردپرس</h2>
	<p>
		با فعال‌سازی پروفایلر، در چند درخواست بعدی (فرانت یا ادمین) زمان لود،
		<strong>کوئری‌های SQL</strong>، <strong>درخواست‌های HTTP</strong> و موارد مشکوک/کند ثبت می‌شوند.
		سپس می‌توانید بهینه‌سازی خودکار را اجرا کنید.
	</p>

	<div class="mvn-actions" style="margin-bottom:16px">
		<?php if ( empty( $arm['active'] ) ) : ?>
			<button type="button" class="button button-primary button-hero" id="mvn-perf-arm">شروع رهگیری (۱۰ دقیقه)</button>
		<?php else : ?>
			<button type="button" class="button" id="mvn-perf-disarm">توقف رهگیری</button>
			<span class="mvn-muted">فعال — باقی‌مانده حدود <?php echo (int) ceil( (int) $arm['remaining'] / 60 ); ?> دقیقه | ثبت‌شده: <?php echo (int) $arm['captured']; ?> / <?php echo (int) $arm['max']; ?></span>
		<?php endif; ?>
		<button type="button" class="button" id="mvn-perf-refresh">تازه‌سازی گزارش</button>
		<button type="button" class="button button-primary" id="mvn-perf-optimize" <?php disabled( ! $has ); ?>>بهینه‌سازی خودکار</button>
		<button type="button" class="button" id="mvn-perf-clear" <?php disabled( ! $has ); ?>>پاک کردن گزارش</button>
		<?php if ( $has && ! empty( $export_url ) ) : ?>
			<a class="button" href="<?php echo esc_url( $export_url ); ?>">خروجی CSV</a>
		<?php else : ?>
			<button type="button" class="button" disabled>خروجی CSV</button>
		<?php endif; ?>
	</div>
	<div id="mvn-perf-notice"></div>

	<?php if ( ! empty( $arm['active'] ) ) : ?>
		<div class="mvn-notice mvn-notice-ok" style="margin-bottom:16px">
			پروفایلر روشن است. یک‌بار صفحه اصلی سایت را در تب جدید باز کنید (یا چند صفحه ادمین را رفرش کنید) تا داده ثبت شود، بعد «تازه‌سازی گزارش» را بزنید.
		</div>
	<?php endif; ?>
</div>

<?php if ( $has ) : ?>
<div class="mvn-grid mvn-grid-4" style="margin-top:16px">
	<div class="mvn-card mvn-stat <?php echo ( ! empty( $report['total_ms'] ) && $report['total_ms'] > 2000 ) ? 'is-warn' : 'is-ok'; ?>">
		<div class="mvn-stat-num"><?php echo esc_html( number_format_i18n( (float) $report['total_ms'], 0 ) ); ?></div>
		<div class="mvn-stat-label">زمان لود (ms)</div>
	</div>
	<div class="mvn-card mvn-stat <?php echo ( ! empty( $report['query_count'] ) && $report['query_count'] > 150 ) ? 'is-warn' : ''; ?>">
		<div class="mvn-stat-num"><?php echo (int) $report['query_count']; ?></div>
		<div class="mvn-stat-label">تعداد کوئری</div>
	</div>
	<div class="mvn-card mvn-stat">
		<div class="mvn-stat-num"><?php echo (int) ( isset( $report['http_count'] ) ? $report['http_count'] : 0 ); ?></div>
		<div class="mvn-stat-label">درخواست HTTP</div>
	</div>
	<div class="mvn-card mvn-stat">
		<div class="mvn-stat-num"><?php echo esc_html( isset( $report['memory_human'] ) ? $report['memory_human'] : '—' ); ?></div>
		<div class="mvn-stat-label">اوج حافظه</div>
	</div>
</div>

<div class="mvn-card" style="margin-top:16px">
	<h2>هشدارها / موارد مشکوک یا کند</h2>
	<?php if ( empty( $report['flags'] ) ) : ?>
		<div class="mvn-empty">مورد پرچم‌دار ثبت نشده.</div>
	<?php else : ?>
		<table class="widefat striped mvn-table">
			<thead>
				<tr>
					<th>شدت</th>
					<th>عنوان</th>
					<th>جزئیات</th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $report['flags'] as $flag ) : ?>
				<tr>
					<td>
						<span class="mvn-badge mvn-badge-<?php echo esc_attr( isset( $flag['severity'] ) ? $flag['severity'] : 'info' ); ?>">
							<?php
							$sev = isset( $flag['severity'] ) ? $flag['severity'] : 'info';
							echo 'critical' === $sev ? 'بحرانی' : ( 'warning' === $sev ? 'هشدار' : 'اطلاع' );
							?>
						</span>
					</td>
					<td><?php echo esc_html( isset( $flag['label'] ) ? $flag['label'] : '' ); ?></td>
					<td class="mvn-path"><code><?php echo esc_html( isset( $flag['detail'] ) ? $flag['detail'] : '' ); ?></code></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
	<p class="mvn-muted">زمان ثبت: <?php echo esc_html( $report['captured_at'] ); ?>
		<?php if ( ! empty( $report['context']['uri'] ) ) : ?>
			— URI: <code><?php echo esc_html( $report['context']['uri'] ); ?></code>
		<?php endif; ?>
	</p>
</div>

<div class="mvn-grid mvn-grid-2" style="margin-top:16px">
	<div class="mvn-card">
		<h2>کندترین کوئری‌های SQL</h2>
		<?php if ( empty( $report['queries'] ) ) : ?>
			<div class="mvn-empty">کوئری ثبت نشد (SAVEQUERIES). یک بار دیگر صفحه را با پروفایلر فعال باز کنید.</div>
		<?php else : ?>
			<table class="widefat striped mvn-table">
				<thead>
					<tr>
						<th>ms</th>
						<th>پرچم</th>
						<th>SQL</th>
						<th>Caller</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( array_slice( $report['queries'], 0, 40 ) as $q ) : ?>
					<tr class="<?php echo ! empty( $q['risk'] ) ? 'mvn-row-risk' : ( ! empty( $q['slow'] ) ? 'mvn-row-slow' : '' ); ?>">
						<td><strong><?php echo esc_html( (string) $q['ms'] ); ?></strong></td>
						<td>
							<?php
							if ( ! empty( $q['flags'] ) ) {
								echo esc_html( implode( ', ', $q['flags'] ) );
							} else {
								echo ! empty( $q['slow'] ) ? 'کند' : '—';
							}
							?>
						</td>
						<td><pre class="mvn-snippet"><?php echo esc_html( $q['sql'] ); ?></pre></td>
						<td><small class="mvn-muted"><?php echo esc_html( isset( $q['caller'] ) ? $q['caller'] : '' ); ?></small></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<?php if ( ! empty( $report['duplicates'] ) ) : ?>
			<h3 style="margin-top:18px">کوئری‌های تکراری</h3>
			<ul class="mvn-kv">
				<?php foreach ( array_slice( $report['duplicates'], 0, 10 ) as $d ) : ?>
					<li>
						<span><?php echo (int) $d['count']; ?>×</span>
						<code><?php echo esc_html( $d['sql'] ); ?></code>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>
	</div>

	<div class="mvn-card">
		<h2>درخواست‌های HTTP هنگام لود</h2>
		<?php if ( empty( $report['http'] ) ) : ?>
			<div class="mvn-empty">در این لود درخواست HTTP خارجی ثبت نشد.</div>
		<?php else : ?>
			<table class="widefat striped mvn-table">
				<thead>
					<tr>
						<th>ms</th>
						<th>کد</th>
						<th>پرچم</th>
						<th>آدرس</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $report['http'] as $h ) : ?>
					<tr class="<?php echo ! empty( $h['risk'] ) ? 'mvn-row-risk' : ( ! empty( $h['slow'] ) ? 'mvn-row-slow' : '' ); ?>">
						<td><strong><?php echo esc_html( (string) $h['ms'] ); ?></strong></td>
						<td><?php echo (int) $h['code']; ?></td>
						<td><?php echo ! empty( $h['flags'] ) ? esc_html( implode( ', ', $h['flags'] ) ) : '—'; ?></td>
						<td class="mvn-path"><code><?php echo esc_html( $h['url'] ); ?></code></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<?php if ( ! empty( $report['autoload']['heavy'] ) ) : ?>
			<h3 style="margin-top:18px">سنگین‌ترین optionهای autoload</h3>
			<?php if ( ! empty( $report['autoload']['orphans'] ) ) : ?>
				<div class="mvn-notice mvn-notice-err" style="margin-bottom:12px">
					<strong>باقی‌مانده پلاگین/قالب حذف‌شده:</strong>
					این optionها هنوز با <code>autoload</code> در هر لود وردپرس به حافظه می‌آیند؛ خود پلاگین اجرا نمی‌شود.
					با «بهینه‌سازی خودکار» حذف می‌شوند.
				</div>
				<ul class="mvn-kv">
					<?php foreach ( $report['autoload']['orphans'] as $o ) : ?>
						<li>
							<span class="mvn-bad"><?php echo esc_html( size_format( (int) $o['bytes'] ) ); ?> — یتیم</span>
							<code><?php echo esc_html( $o['option_name'] ); ?></code>
							<small class="mvn-muted"><?php echo esc_html( isset( $o['source'] ) ? $o['source'] : '' ); ?></small>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
			<ul class="mvn-kv">
				<?php foreach ( $report['autoload']['heavy'] as $o ) : ?>
					<li>
						<span><?php echo esc_html( size_format( (int) $o['bytes'] ) ); ?></span>
						<code><?php echo esc_html( $o['option_name'] ); ?></code>
					</li>
				<?php endforeach; ?>
			</ul>
			<p class="mvn-muted">جمع autoload: <?php echo esc_html( size_format( (int) $report['autoload']['total_bytes'] ) ); ?> / <?php echo (int) $report['autoload']['count']; ?> مورد</p>
		<?php endif; ?>
	</div>
</div>
<?php else : ?>
<div class="mvn-card" style="margin-top:16px">
	<div class="mvn-empty">هنوز گزارشی ثبت نشده. «شروع رهگیری» را بزنید، سپس صفحه اصلی سایت را باز کنید.</div>
</div>
<?php endif; ?>

<?php if ( ! empty( $blocked ) ) : ?>
<div class="mvn-card" style="margin-top:16px">
	<h2>دامنه‌های مسدودشده (HTTP)</h2>
	<p class="mvn-muted">این دامنه‌ها هنگام لود بلاک می‌شوند (نتیجه بهینه‌سازی یا مسدودسازی دستی).</p>
	<ul class="mvn-kv">
		<?php foreach ( $blocked as $host ) : ?>
			<li><span>blocked</span><code><?php echo esc_html( $host ); ?></code></li>
		<?php endforeach; ?>
	</ul>
</div>
<?php endif; ?>
