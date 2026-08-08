<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$count = is_array( $issues ) ? count( $issues ) : 0;
$ac    = isset( $action_counts ) && is_array( $action_counts ) ? $action_counts : array();
$safe_n = isset( $ac['safe_fixable'] ) ? (int) $ac['safe_fixable'] : 0;
$fixable = isset( $ac['fixable'] ) ? (int) $ac['fixable'] : $count;
$repair_url = admin_url( 'admin.php?page=mvn-repair' );
?>
<div class="mvn-card">
	<h2>رفع مشکلات یافت‌شده</h2>
	<p>
		سیاست پیش‌فرض: <strong>رفع امن</strong> — فقط مواردی که وردپرس را از کار نمی‌اندازند
		(حذف PHP در uploads، فایل اضافی هسته، تعمیر فایل هسته، پاکسازی اسپم DB، option مشکوک).
	</p>
	<p class="mvn-muted">
		موارد «احتیاط / دستی» (پاکسازی injection در پلاگین/قالب، قرنطینه کل فایل، فایل گم‌شده مخزن)
		در رفع امن اجرا نمی‌شوند تا سایت سفید نشود.
		برای فایل‌های گم‌شده/تغییر یافته مخزن از
		<a href="<?php echo esc_url( $repair_url ); ?>">تعمیر پلاگین/هسته</a>
		استفاده کنید.
	</p>
	<p class="mvn-muted">
		یافته‌ها بر اساس <strong>امتیاز اطمینان</strong> مرتب شده‌اند. برای مثبت کاذب از «امن است» استفاده کنید.
	</p>
	<p class="mvn-muted">
		عمل <code>quarantine</code> فایل را ایزوله می‌کند (کپی + حذف). روی فایل‌های حیاتی قالب/پلاگین مسدود شده است.
	</p>

	<?php if ( 0 === $count ) : ?>
		<div class="mvn-empty">مشکل بازی وجود ندارد. ابتدا یک اسکن اجرا کنید.</div>
	<?php else : ?>
		<div class="mvn-actions mvn-fix-actions" style="margin-bottom:16px">
			<button type="button" class="button button-primary mvn-fix-batch" id="mvn-fix-safe" data-filter="safe" <?php disabled( $safe_n <= 0 ); ?>>رفع امن<?php echo $safe_n > 0 ? ' (' . (int) $safe_n . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-htaccess" data-filter="delete_htaccess" <?php disabled( empty( $ac['delete_htaccess'] ) ); ?>>حذف htaccess جعلی<?php echo ! empty( $ac['delete_htaccess'] ) ? ' (' . (int) $ac['delete_htaccess'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-uploads" data-filter="quarantine_delete" <?php disabled( empty( $ac['quarantine_delete'] ) ); ?>>حذف PHP uploads<?php echo ! empty( $ac['quarantine_delete'] ) ? ' (' . (int) $ac['quarantine_delete'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-core-file" data-filter="core_repair_file" <?php disabled( empty( $ac['core_repair_file'] ) ); ?>>تعمیر فایل هسته<?php echo ! empty( $ac['core_repair_file'] ) ? ' (' . (int) $ac['core_repair_file'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-core-extra" data-filter="delete_core_extra" <?php disabled( empty( $ac['delete_core_extra'] ) ); ?>>حذف فایل اضافی هسته<?php echo ! empty( $ac['delete_core_extra'] ) ? ' (' . (int) $ac['delete_core_extra'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-db-clean" data-filter="db_clean" <?php disabled( empty( $ac['db_clean'] ) ); ?>>پاکسازی DB<?php echo ! empty( $ac['db_clean'] ) ? ' (' . (int) $ac['db_clean'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-db-option" data-filter="db_delete_option" <?php disabled( empty( $ac['db_delete_option'] ) ); ?>>حذف option مشکوک<?php echo ! empty( $ac['db_delete_option'] ) ? ' (' . (int) $ac['db_delete_option'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-as-delete" data-filter="as_delete" <?php disabled( empty( $ac['as_delete'] ) ); ?>>حذف AS مشکوک<?php echo ! empty( $ac['as_delete'] ) ? ' (' . (int) $ac['as_delete'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-clean" data-filter="clean" <?php disabled( empty( $ac['clean'] ) ); ?>>پاکسازی injection<?php echo ! empty( $ac['clean'] ) ? ' (' . (int) $ac['clean'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch mvn-fix-risky" id="mvn-fix-all" data-filter="all" <?php disabled( $fixable <= 0 ); ?> title="ممکن است پلاگین/قالب را بشکند">رفع پرخطر (همه)<?php echo $fixable > 0 ? ' (' . (int) $fixable . ')' : ''; ?></button>
			<a class="button" href="<?php echo esc_url( $export_url ); ?>">خروجی CSV</a>
			<button type="button" class="button" id="mvn-fix-clear">پاک کردن لیست (اسکن مجدد)</button>
		</div>
		<div id="mvn-fix-progress" class="mvn-progress-wrap" style="display:none;margin-bottom:16px">
			<div class="mvn-progress"><div class="mvn-progress-bar" id="mvn-fix-bar" style="width:0%"></div></div>
			<div class="mvn-progress-meta"><span id="mvn-fix-label">در حال رفع...</span></div>
		</div>

		<table class="widefat striped mvn-table" id="mvn-issues-table">
			<thead>
				<tr>
					<th>اطمینان</th>
					<th>ریسک رفع</th>
					<th>شدت</th>
					<th>مکان</th>
					<th>نوع تهدید</th>
					<th>اقدام</th>
					<th>نمونه کد</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $issues as $iss ) :
				$conf = isset( $iss['confidence'] ) ? (int) $iss['confidence'] : 0;
				$conf_class = function_exists( 'mvn_confidence_class' ) ? mvn_confidence_class( $conf ) : 'low';
				$conf_label = isset( $iss['conf_label'] ) ? $iss['conf_label'] : ( function_exists( 'mvn_confidence_label' ) ? mvn_confidence_label( $conf ) : '' );
				$risk = class_exists( 'MVN_Cleaner' ) ? MVN_Cleaner::risk_tier( $iss ) : 'caution';
				$risk_label = class_exists( 'MVN_Cleaner' ) ? MVN_Cleaner::risk_label( $risk ) : $risk;
				$action_show = class_exists( 'MVN_Cleaner' ) ? MVN_Cleaner::normalized_action( $iss ) : ( isset( $iss['action'] ) ? $iss['action'] : '' );
				?>
				<tr data-id="<?php echo esc_attr( $iss['id'] ); ?>" data-risk="<?php echo esc_attr( $risk ); ?>">
					<td class="mvn-conf-cell">
						<div class="mvn-conf-bar-wrap" title="<?php echo esc_attr( $conf . '% — ' . $conf_label ); ?>">
							<div class="mvn-conf-bar mvn-conf-<?php echo esc_attr( $conf_class ); ?>" style="width:<?php echo (int) $conf; ?>%"></div>
						</div>
						<span class="mvn-conf-num"><?php echo (int) $conf; ?>%</span>
						<small class="mvn-muted mvn-conf-label"><?php echo esc_html( $conf_label ); ?></small>
					</td>
					<td>
						<span class="mvn-badge mvn-risk-<?php echo esc_attr( $risk ); ?>"><?php echo esc_html( $risk_label ); ?></span>
					</td>
					<td>
						<span class="mvn-badge mvn-badge-<?php echo esc_attr( $iss['severity'] ); ?>">
							<?php echo 'critical' === $iss['severity'] ? 'بحرانی' : ( 'warning' === $iss['severity'] ? 'هشدار' : 'اطلاع' ); ?>
						</span>
					</td>
					<td class="mvn-path">
						<?php if ( ! empty( $iss['source'] ) && 'db' === $iss['source'] ) : ?>
							<span class="mvn-badge mvn-badge-info">DB</span>
							<code><?php echo esc_html( $iss['rel'] ); ?></code>
							<?php if ( ! empty( $iss['table'] ) ) : ?>
								<br><small class="mvn-muted"><?php echo esc_html( $iss['table'] ); ?> / <?php echo esc_html( isset( $iss['column'] ) ? $iss['column'] : '' ); ?></small>
							<?php endif; ?>
						<?php elseif ( ! empty( $iss['source'] ) && 'as' === $iss['source'] ) : ?>
							<span class="mvn-badge mvn-badge-warning">AS</span>
							<code><?php echo esc_html( $iss['rel'] ); ?></code>
							<?php if ( ! empty( $iss['hook'] ) ) : ?>
								<br><small class="mvn-muted">hook: <?php echo esc_html( $iss['hook'] ); ?><?php echo ! empty( $iss['as_status'] ) ? ' [' . esc_html( $iss['as_status'] ) . ']' : ''; ?></small>
							<?php endif; ?>
						<?php elseif ( ! empty( $iss['source'] ) && 'core' === $iss['source'] ) : ?>
							<span class="mvn-badge mvn-badge-critical">CORE</span>
							<code><?php echo esc_html( $iss['rel'] ); ?></code>
							<?php if ( ! empty( $iss['expected_hash'] ) ) : ?>
								<br><small class="mvn-muted">MD5: <?php echo esc_html( isset( $iss['actual_hash'] ) ? $iss['actual_hash'] : '—' ); ?></small>
							<?php endif; ?>
						<?php else : ?>
							<code><?php echo esc_html( $iss['rel'] ); ?></code>
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( $iss['label'] ); ?><?php echo ! empty( $iss['detail'] ) ? '<br><small class="mvn-muted">' . esc_html( $iss['detail'] ) . '</small>' : ''; ?></td>
					<td><code><?php echo esc_html( $action_show ); ?></code></td>
					<td><pre class="mvn-snippet"><?php echo esc_html( isset( $iss['snippet'] ) ? $iss['snippet'] : '' ); ?></pre></td>
					<td class="mvn-actions-cell">
						<?php if ( 'repo_repair' === $action_show ) : ?>
							<a class="button button-small" href="<?php echo esc_url( $repair_url ); ?>">تعمیر پلاگین</a>
						<?php elseif ( 'manual' === $risk ) : ?>
							<button type="button" class="button button-small mvn-fix-one" data-id="<?php echo esc_attr( $iss['id'] ); ?>" title="ممکن است نیاز به بررسی داشته باشد">بررسی/رفع</button>
						<?php else : ?>
							<button type="button" class="button button-small mvn-fix-one" data-id="<?php echo esc_attr( $iss['id'] ); ?>">رفع</button>
						<?php endif; ?>
						<button type="button" class="button button-small mvn-ignore-one" data-id="<?php echo esc_attr( $iss['id'] ); ?>" title="این مورد امن است و در اسکن‌های بعدی نادیده گرفته می‌شود">امن است</button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
