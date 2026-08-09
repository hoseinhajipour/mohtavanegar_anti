<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$count = is_array( $items ) ? count( $items ) : 0;
?>
<div class="mvn-card">
	<h2>قرنطینه</h2>
	<p>قبل از هر حذف یا پاکسازی، یک snapshot در data-dir امن ذخیره می‌شود. بازیابی payload آلوده پیش‌فرض مسدود است.</p>

	<?php if ( 0 === $count ) : ?>
		<div class="mvn-empty">قرنطینه خالی است.</div>
	<?php else : ?>
		<div class="mvn-actions mvn-q-bulk-bar" style="margin-bottom:16px">
			<button type="button" class="button button-primary" id="mvn-q-restore-selected" disabled>بازیابی انتخاب‌شده</button>
			<button type="button" class="button" id="mvn-q-purge-selected" disabled>حذف دائمی انتخاب‌شده</button>
			<span class="mvn-muted mvn-q-selected-count" id="mvn-q-selected-count"></span>
		</div>
		<div id="mvn-q-progress" class="mvn-progress-wrap" style="display:none;margin-bottom:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-q-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta"><span id="mvn-q-label">در حال پردازش...</span></div>
		</div>

		<table class="widefat striped mvn-table" id="mvn-quarantine-table">
			<thead>
				<tr>
					<th class="mvn-check-col">
						<input type="checkbox" id="mvn-q-select-all" title="انتخاب همه">
					</th>
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
					<td class="mvn-check-col">
						<input type="checkbox" class="mvn-q-check" value="<?php echo esc_attr( $item['id'] ); ?>">
					</td>
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
