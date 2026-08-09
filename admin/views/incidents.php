<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$incidents = isset( $incidents ) && is_array( $incidents ) ? $incidents : array();
?>
<div class="mvn-card">
	<h2>Incidents</h2>
	<p class="mvn-muted">چرخهٔ عمر تهدید: Open → Quarantined / Fixed → Verified — یا Reinfection.</p>
	<?php if ( empty( $incidents ) ) : ?>
		<div class="mvn-empty">هنوز incidentی ثبت نشده.</div>
	<?php else : ?>
		<table class="widefat striped mvn-table">
			<thead>
				<tr>
					<th>شناسه</th>
					<th>وضعیت</th>
					<th>تهدید</th>
					<th>مسیر</th>
					<th>آخرین مشاهده</th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $incidents as $id => $row ) :
				$f = isset( $row['finding'] ) ? $row['finding'] : array();
				?>
				<tr>
					<td><code><?php echo esc_html( substr( (string) $id, 0, 12 ) ); ?></code></td>
					<td><span class="mvn-badge"><?php echo esc_html( isset( $row['status'] ) ? $row['status'] : '' ); ?></span></td>
					<td><?php echo esc_html( isset( $f['label'] ) ? $f['label'] : ( isset( $f['sig'] ) ? $f['sig'] : '' ) ); ?></td>
					<td><code><?php echo esc_html( isset( $f['rel'] ) ? $f['rel'] : '' ); ?></code></td>
					<td><?php echo esc_html( isset( $row['last_seen'] ) ? $row['last_seen'] : ( isset( $row['updated_at'] ) ? $row['updated_at'] : '' ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
