<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="mvn-card">
	<h2>قرنطینه</h2>
	<p>قبل از هر حذف یا پاکسازی، یک کپی از فایل در <code>wp-content/mvn-data/quarantine</code> ذخیره می‌شود. می‌توانید بازیابی یا حذف دائمی کنید.</p>

	<?php if ( empty( $items ) ) : ?>
		<div class="mvn-empty">قرنطینه خالی است.</div>
	<?php else : ?>
		<table class="widefat striped mvn-table">
			<thead>
				<tr>
					<th>زمان</th>
					<th>مسیر اصلی</th>
					<th>دلیل</th>
					<th>حجم</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $items as $item ) : ?>
				<tr data-qid="<?php echo esc_attr( $item['id'] ); ?>">
					<td><?php echo esc_html( isset( $item['created_at'] ) ? $item['created_at'] : '' ); ?></td>
					<td class="mvn-path"><code><?php echo esc_html( isset( $item['rel'] ) ? $item['rel'] : '' ); ?></code></td>
					<td><?php echo esc_html( isset( $item['reason'] ) ? $item['reason'] : '' ); ?></td>
					<td><?php echo esc_html( mvn_size_format( isset( $item['size'] ) ? $item['size'] : 0 ) ); ?></td>
					<td class="mvn-actions-cell">
						<button type="button" class="button button-small mvn-q-restore" data-id="<?php echo esc_attr( $item['id'] ); ?>">بازیابی</button>
						<button type="button" class="button button-small button-link-delete mvn-q-purge" data-id="<?php echo esc_attr( $item['id'] ); ?>">حذف دائمی</button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
