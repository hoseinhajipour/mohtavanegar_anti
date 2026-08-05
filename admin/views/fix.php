<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$count = is_array( $issues ) ? count( $issues ) : 0;
?>
<div class="mvn-card">
	<h2>رفع مشکلات یافت‌شده</h2>
	<p>
		بعد از اسکن، موارد اینجا لیست می‌شوند. برای کدهای تزریق‌شده، پلاگین سعی می‌کند فقط تکه مخرب را پاک کند.
		برای <code>.htaccess</code> های جعلی و PHP داخل uploads، فایل بعد از قرنطینه حذف می‌شود.
	</p>

	<?php if ( 0 === $count ) : ?>
		<div class="mvn-empty">مشکل بازی وجود ندارد. ابتدا یک اسکن اجرا کنید.</div>
	<?php else : ?>
		<div class="mvn-actions" style="margin-bottom:16px">
			<button type="button" class="button button-primary" id="mvn-fix-all" data-filter="">رفع همه (دسته‌ای)</button>
			<button type="button" class="button" id="mvn-fix-htaccess" data-filter="delete_htaccess">حذف همه htaccess جعلی</button>
			<button type="button" class="button" id="mvn-fix-clean" data-filter="clean">پاکسازی کدهای تزریق‌شده</button>
			<button type="button" class="button" id="mvn-fix-uploads" data-filter="quarantine_delete">حذف PHPهای uploads</button>
			<button type="button" class="button" id="mvn-fix-clear">پاک کردن لیست (اسکن مجدد)</button>
		</div>
		<div id="mvn-fix-progress" class="mvn-progress-wrap" style="display:none;margin-bottom:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-fix-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta"><span id="mvn-fix-label">در حال رفع...</span></div>
		</div>

		<table class="widefat striped mvn-table" id="mvn-issues-table">
			<thead>
				<tr>
					<th>شدت</th>
					<th>فایل</th>
					<th>نوع تهدید</th>
					<th>اقدام</th>
					<th>نمونه کد</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $issues as $iss ) : ?>
				<tr data-id="<?php echo esc_attr( $iss['id'] ); ?>">
					<td>
						<span class="mvn-badge mvn-badge-<?php echo esc_attr( $iss['severity'] ); ?>">
							<?php echo 'critical' === $iss['severity'] ? 'بحرانی' : ( 'warning' === $iss['severity'] ? 'هشدار' : 'اطلاع' ); ?>
						</span>
					</td>
					<td class="mvn-path"><code><?php echo esc_html( $iss['rel'] ); ?></code></td>
					<td><?php echo esc_html( $iss['label'] ); ?><?php echo ! empty( $iss['detail'] ) ? '<br><small class="mvn-muted">' . esc_html( $iss['detail'] ) . '</small>' : ''; ?></td>
					<td><code><?php echo esc_html( isset( $iss['action'] ) ? $iss['action'] : '' ); ?></code></td>
					<td><pre class="mvn-snippet"><?php echo esc_html( isset( $iss['snippet'] ) ? $iss['snippet'] : '' ); ?></pre></td>
					<td><button type="button" class="button button-small mvn-fix-one" data-id="<?php echo esc_attr( $iss['id'] ); ?>">رفع</button></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
