<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$cron = isset( $cron ) && is_array( $cron ) ? $cron : array();
$logs = isset( $logs ) && is_array( $logs ) ? $logs : array();
?>
<div class="mvn-card">
	<h2>Cron Monitor</h2>
	<p class="mvn-muted">رویدادهای WP-Cron. موارد پرریسک (xdav/zonal/…) را بررسی کنید. Cron سیستم‌عامل فقط گزارش می‌شود و تغییر داده نمی‌شود.</p>
	<?php if ( empty( $cron ) ) : ?>
		<div class="mvn-empty">رویداد کرونی یافت نشد.</div>
	<?php else : ?>
		<table class="widefat striped mvn-table">
			<thead>
				<tr><th>Hook</th><th>Next</th><th>Count</th><th>Risk</th></tr>
			</thead>
			<tbody>
			<?php foreach ( array_slice( $cron, 0, 200 ) as $row ) : ?>
				<tr class="<?php echo (int) $row['risk_score'] >= 80 ? 'mvn-row-risk' : ''; ?>">
					<td><code><?php echo esc_html( $row['hook'] ); ?></code></td>
					<td><?php echo esc_html( $row['next_human'] ); ?></td>
					<td><?php echo (int) $row['count']; ?></td>
					<td><?php echo (int) $row['risk_score']; ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
<div class="mvn-card">
	<h3>Security Log (اخیر)</h3>
	<?php if ( empty( $logs ) ) : ?>
		<p class="mvn-muted">لاگی نیست.</p>
	<?php else : ?>
		<table class="widefat striped mvn-table">
			<thead><tr><th>زمان</th><th>عمل</th><th>هدف</th><th>نتیجه</th></tr></thead>
			<tbody>
			<?php foreach ( $logs as $log ) : ?>
				<tr>
					<td><?php echo esc_html( isset( $log['timestamp'] ) ? $log['timestamp'] : '' ); ?></td>
					<td><?php echo esc_html( isset( $log['action'] ) ? $log['action'] : '' ); ?></td>
					<td><code><?php echo esc_html( isset( $log['target'] ) ? $log['target'] : '' ); ?></code></td>
					<td><?php echo esc_html( isset( $log['result'] ) ? $log['result'] : '' ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
