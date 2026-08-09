<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$findings = isset( $findings ) && is_array( $findings ) ? $findings : array();
$watched  = isset( $watched ) && is_array( $watched ) ? $watched : array();
?>
<div class="mvn-card">
	<h2>Persistence / Reinfection</h2>
	<p class="mvn-muted">منابع پایدار که می‌توانند بدافزار (مثل xdav-tracker) را دوباره بسازند. قبل از حذف، Dry Run بزنید.</p>
	<p>
		مسیرهای تحت نظر: <strong><?php echo (int) count( $watched ); ?></strong>
		—
		<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-scan' ) ); ?>">اسکن مجدد</a>
		<button type="button" class="button" id="mvn-persistence-selftest">Self-test Persistence</button>
	</p>
	<?php if ( empty( $findings ) ) : ?>
		<div class="mvn-empty">منبع Persistence بازی در لیست یافته‌ها نیست. یک اسکن کامل اجرا کنید.</div>
	<?php else : ?>
		<table class="widefat striped mvn-table">
			<thead>
				<tr>
					<th>مسیر</th>
					<th>امتیاز</th>
					<th>جزئیات</th>
					<th>همبستگی</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $findings as $f ) : ?>
				<tr>
					<td><code><?php echo esc_html( isset( $f['rel'] ) ? $f['rel'] : '' ); ?></code></td>
					<td><?php echo (int) ( isset( $f['risk_score'] ) ? $f['risk_score'] : ( isset( $f['confidence'] ) ? $f['confidence'] : 0 ) ); ?></td>
					<td><?php echo esc_html( isset( $f['detail'] ) ? $f['detail'] : '' ); ?></td>
					<td>
						<?php
						$pers = isset( $f['persistence'] ) && is_array( $f['persistence'] ) ? $f['persistence'] : array();
						foreach ( array_slice( $pers, 0, 3 ) as $p ) {
							echo esc_html( ( isset( $p['type'] ) ? $p['type'] : '?' ) . ': ' . ( isset( $p['path'] ) ? $p['path'] : '' ) ) . '<br>';
						}
						?>
					</td>
					<td>
						<button type="button" class="button button-small mvn-dry-run" data-id="<?php echo esc_attr( isset( $f['id'] ) ? $f['id'] : '' ); ?>">Dry Run</button>
						<button type="button" class="button button-small button-primary mvn-remediate" data-id="<?php echo esc_attr( isset( $f['id'] ) ? $f['id'] : '' ); ?>">رفع Persistence-first</button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<pre id="mvn-dry-run-out" class="mvn-snippet" style="margin-top:12px;display:none"></pre>
	<?php endif; ?>

	<?php if ( ! empty( $watched ) ) : ?>
		<h3>مسیرهای Watched (Reinfection Monitor)</h3>
		<ul>
			<?php foreach ( $watched as $rel => $meta ) : ?>
				<li><code><?php echo esc_html( $rel ); ?></code>
					<small class="mvn-muted">hits=<?php echo (int) ( isset( $meta['hits'] ) ? $meta['hits'] : 0 ); ?></small>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php endif; ?>
</div>
