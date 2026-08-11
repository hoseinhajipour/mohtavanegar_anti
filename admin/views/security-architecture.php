<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$p         = isset( $payload ) && is_array( $payload ) ? $payload : array();
$state     = isset( $p['state'] ) && is_array( $p['state'] ) ? $p['state'] : array();
$status    = isset( $state['status'] ) ? (string) $state['status'] : 'not_started';
$completed = ! empty( $p['completed'] );
$busy      = ! empty( $p['busy'] );
$public    = isset( $p['public_path'] ) ? (string) $p['public_path'] : '';
$wp_path   = isset( $p['wordpress_path'] ) ? (string) $p['wordpress_path'] : '';
$proposed  = isset( $p['proposed_core'] ) ? (string) $p['proposed_core'] : '';
$gateway   = isset( $p['gateway_path'] ) ? (string) $p['gateway_path'] : '';
$log_lines = isset( $p['log_lines'] ) && is_array( $p['log_lines'] ) ? $p['log_lines'] : array();
$ver       = isset( $state['verification'] ) && is_array( $state['verification'] ) ? $state['verification'] : array();
$preflight = isset( $preflight_result ) && is_array( $preflight_result ) ? $preflight_result : null;
?>
<div class="mvn-card" id="mvn-security-arch">
	<h2>معماری امنیتی وردپرس (Security Gateway)</h2>
	<p>
		این قابلیت هسته وردپرس را به خارج از ریشه وب (<code>public_html</code>) منتقل می‌کند و یک Gateway سبک در ریشه عمومی قرار می‌دهد.
		آدرس سایت تغییر نمی‌کند. قبل از هر تغییر، بک‌آپ و آزمون پیش‌نیاز انجام می‌شود.
	</p>

	<?php if ( $completed ) : ?>
		<div class="mvn-notice mvn-notice-ok">
			✓ Security Gateway فعال است
		</div>
		<table class="form-table mvn-form-table">
			<tr>
				<th>هسته وردپرس</th>
				<td dir="ltr"><code><?php echo esc_html( $wp_path ); ?></code></td>
			</tr>
			<tr>
				<th>ریشه وب عمومی</th>
				<td dir="ltr"><code><?php echo esc_html( $public ); ?></code></td>
			</tr>
			<tr>
				<th>Gateway</th>
				<td dir="ltr"><code><?php echo esc_html( $gateway ); ?></code></td>
			</tr>
			<tr>
				<th>وضعیت</th>
				<td>
					<?php if ( ! empty( $state['gateway_healthy'] ) ) : ?>
						<span class="mvn-badge mvn-badge-info">Healthy</span>
					<?php else : ?>
						<span class="mvn-badge mvn-badge-warning">نیاز به بررسی</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th>تاریخ مهاجرت</th>
				<td><?php echo esc_html( isset( $state['completed_at'] ) ? $state['completed_at'] : '' ); ?> UTC</td>
			</tr>
			<tr>
				<th>آخرین تأیید</th>
				<td><?php echo esc_html( isset( $state['last_verification'] ) ? $state['last_verification'] : '—' ); ?> UTC</td>
			</tr>
		</table>

		<div class="mvn-actions" style="gap:8px;flex-wrap:wrap">
			<button type="button" class="button" id="mvn-sec-reverify">اجرای مجدد تأیید سلامت</button>
			<button type="button" class="button" id="mvn-sec-repair-uploads"
				title="chmod 0644 روی فایل‌های uploads — رفع 403 بندانگشتی در Media Library">
				تعمیر دسترسی رسانه (uploads)
			</button>
			<button type="button" class="button button-link-delete" id="mvn-sec-rollback"
				data-confirm="بازگشت به معماری قبلی انجام شود؟ سایت موقتاً در حالت نگهداری قرار می‌گیرد.">
				بازگردانی معماری امنیتی وردپرس
			</button>
			<span id="mvn-sec-result"></span>
		</div>
		<p class="description" style="margin-top:8px">
			اگر بعد از مهاجرت تصویر در کتابخانه رسانه / تصویر شاخص دیده نمی‌شود ولی لینک اصلی فایل باز می‌شود،
			معمولاً سایزهای بندانگشتی با دسترسی <code>0600</code> ساخته شده‌اند و LiteSpeed آن‌ها را با HTTP 403 رد می‌کند.
			دکمه «تعمیر دسترسی رسانه» را بزنید.
		</p>
	<?php else : ?>
		<div class="mvn-grid-2" style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
			<div>
				<h3>ساختار فعلی</h3>
				<table class="form-table mvn-form-table">
					<tr>
						<th>ریشه عمومی</th>
						<td dir="ltr"><code><?php echo esc_html( $public ); ?></code></td>
					</tr>
					<tr>
						<th>وردپرس</th>
						<td dir="ltr"><code><?php echo esc_html( $wp_path ); ?></code></td>
					</tr>
					<tr>
						<th>Security Gateway</th>
						<td><span class="mvn-badge mvn-badge-warning">غیرفعال</span></td>
					</tr>
				</table>
			</div>
			<div>
				<h3>ساختار پیشنهادی</h3>
				<table class="form-table mvn-form-table">
					<tr>
						<th>ریشه عمومی</th>
						<td dir="ltr"><code><?php echo esc_html( $public ); ?></code></td>
					</tr>
					<tr>
						<th>وردپرس</th>
						<td dir="ltr"><code><?php echo esc_html( $proposed ); ?></code></td>
					</tr>
					<tr>
						<th>Security Gateway</th>
						<td><span class="mvn-badge mvn-badge-info">فعال</span></td>
					</tr>
				</table>
			</div>
		</div>

		<div class="mvn-notice mvn-notice-err" style="margin-top:12px">
			<strong>هشدار:</strong>
			این عملیات فایل‌های وردپرس را کپی می‌کند، ریشه عمومی را به Gateway تغییر می‌دهد و به symlink نیاز دارد.
			قبل از اجرا از بک‌آپ کامل میزبانی مطمئن شوید. در صورت شکست آزمون‌ها، بازگشت خودکار انجام می‌شود.
			آدرس عمومی سایت (<code dir="ltr"><?php echo esc_html( isset( $p['home_url'] ) ? $p['home_url'] : '' ); ?></code>) تغییر نمی‌کند.
		</div>

		<?php if ( 'failed' === $status && ! empty( $state['error'] ) ) : ?>
			<div class="mvn-notice mvn-notice-err">
				آخرین خطا: <?php echo esc_html( $state['error'] ); ?>
			</div>
		<?php endif; ?>

		<?php if ( $busy ) : ?>
			<div class="mvn-notice mvn-notice-ok">
				مهاجرت ناتمام در وضعیت <code><?php echo esc_html( $status ); ?></code> متوقف شده است
				<?php if ( ! empty( $state['copy_total'] ) ) : ?>
					— پیشرفت کپی: <?php echo (int) $state['copy_offset']; ?> / <?php echo (int) $state['copy_total']; ?>
				<?php endif; ?>
				. می‌توانید ادامه دهید یا لغو کنید.
			</div>
		<?php endif; ?>

		<div class="mvn-actions" style="margin-top:14px;gap:8px;flex-wrap:wrap">
			<button type="button" class="button" id="mvn-sec-preflight">اجرای پیش‌نیاز امنیتی</button>
			<button type="button" class="button button-primary" id="mvn-sec-migrate"
				data-confirm="وردپرس به خارج از ریشه وب منتقل شود؟ این کار برگشت‌پذیر است اما سنگین است. ادامه می‌دهید؟">
				<?php echo $busy ? 'ادامه مهاجرت' : 'انتقال وردپرس به خارج از ریشه وب'; ?>
			</button>
			<?php if ( $busy || 'failed' === $status ) : ?>
				<button type="button" class="button button-link-delete" id="mvn-sec-abort"
					data-confirm="مهاجرت ناتمام لغو شود و کپی ناقص پاک گردد؟">
					لغو مهاجرت ناتمام
				</button>
			<?php endif; ?>
			<span id="mvn-sec-result"></span>
		</div>

		<div id="mvn-sec-progress-wrap" class="mvn-progress-wrap" style="<?php echo $busy ? '' : 'display:none;'; ?>margin-top:14px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-sec-progress-bar" style="width:<?php echo $busy && ! empty( $state['copy_total'] ) ? min( 95, (int) round( ( (int) $state['copy_offset'] / max( 1, (int) $state['copy_total'] ) ) * 80 ) + 10 ) : 0; ?>%"></div></div>
			<p class="mvn-progress-meta" id="mvn-sec-progress-label"><?php echo $busy ? 'آماده ادامه…' : '…'; ?></p>
		</div>
	<?php endif; ?>

	<div id="mvn-sec-preflight-box" style="margin-top:18px">
		<?php if ( $preflight ) : ?>
			<h3>نتیجه پیش‌نیاز</h3>
			<table class="widefat striped mvn-table">
				<thead>
					<tr><th>بررسی</th><th>وضعیت</th><th>جزئیات</th></tr>
				</thead>
				<tbody>
					<?php foreach ( $preflight['checks'] as $c ) : ?>
						<tr>
							<td><?php echo esc_html( $c['label'] ); ?></td>
							<td>
								<?php if ( ! empty( $c['ok'] ) ) : ?>
									<span class="mvn-badge mvn-badge-info">OK</span>
								<?php else : ?>
									<span class="mvn-badge mvn-badge-critical">FAIL</span>
								<?php endif; ?>
							</td>
							<td class="mvn-path" dir="ltr"><code><?php echo esc_html( $c['detail'] ); ?></code></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

	<?php if ( ! empty( $ver['tests'] ) ) : ?>
		<h3 style="margin-top:18px">آخرین آزمون‌های تأیید</h3>
		<table class="widefat striped mvn-table">
			<thead>
				<tr><th>آزمون</th><th>وضعیت</th><th>جزئیات</th></tr>
			</thead>
			<tbody>
				<?php foreach ( $ver['tests'] as $t ) : ?>
					<tr>
						<td><?php echo esc_html( $t['label'] ); ?></td>
						<td>
							<?php if ( ! empty( $t['ok'] ) ) : ?>
								<span class="mvn-badge mvn-badge-info">OK</span>
							<?php else : ?>
								<span class="mvn-badge mvn-badge-critical">FAIL</span>
							<?php endif; ?>
						</td>
						<td class="mvn-path" dir="ltr"><code><?php echo esc_html( $t['detail'] ); ?></code></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<?php if ( $log_lines ) : ?>
		<h3 style="margin-top:18px">لاگ مهاجرت</h3>
		<pre class="mvn-log" id="mvn-sec-log" dir="ltr" style="max-height:260px;overflow:auto;background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;font-size:12px"><?php
			echo esc_html( implode( "\n", $log_lines ) );
		?></pre>
	<?php else : ?>
		<pre class="mvn-log" id="mvn-sec-log" dir="ltr" style="display:none;max-height:260px;overflow:auto;background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;font-size:12px"></pre>
	<?php endif; ?>
</div>
