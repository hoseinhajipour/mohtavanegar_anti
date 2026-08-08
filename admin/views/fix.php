<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$count = is_array( $issues ) ? count( $issues ) : 0;
$ac    = isset( $action_counts ) && is_array( $action_counts ) ? $action_counts : array();
$fixable = isset( $ac['fixable'] ) ? (int) $ac['fixable'] : $count;
?>
<div class="mvn-card">
	<h2>رفع مشکلات یافت‌شده</h2>
	<p>
		بعد از اسکن، موارد اینجا لیست می‌شوند. برای کدهای تزریق‌شده در <strong>پلاگین‌ها و قالب‌ها</strong>، پلاگین سعی می‌کند فقط تکه مخرب را پاک کند.
		برای <code>.htaccess</code> های جعلی و PHP داخل uploads، فایل بعد از قرنطینه حذف می‌شود.
	</p>
	<p class="mvn-muted">
		یافته‌ها بر اساس <strong>امتیاز اطمینان</strong> مرتب شده‌اند. برای موارد اشتباه (false positive) از دکمه «امن است» استفاده کنید تا در اسکن‌های بعدی نادیده گرفته شوند.
	</p>
	<p class="mvn-muted">
		<strong>یافته‌های هسته (checksum)</strong> —
		فایل‌های <em>تغییر یافته / گم‌شده</em> را می‌توانید با دکمه «رفع» یا «تعمیر فایل هسته» از zip بازگردانید؛
		فایل‌های <em>اضافی</em> بعد از قرنطینه حذف می‌شوند.
		برای جایگزینی کامل از <a href="<?php echo esc_url( admin_url( 'admin.php?page=mvn-repair' ) ); ?>">تعمیر هسته</a> استفاده کنید.
	</p>
	<p class="mvn-muted">
		<strong>یافته‌های دیتابیس</strong> (شروع با <code>db:</code>) ممکن است نیاز به بررسی دستی داشته باشند — مخصوصاً کاربران ادمین مشکوک. optionهای محافظت‌شده وردپرس هرگز خودکار حذف نمی‌شوند.
	</p>
	<p class="mvn-muted">
		<strong>یافته‌های Action Scheduler</strong> (شروع با <code>as:</code>) اقدامات زمان‌بندی‌شده مشکوک هستند؛ با «حذف AS مشکوک» بعد از پشتیبان‌گیری در قرنطینه پاک می‌شوند.
	</p>
	<p class="mvn-muted">
		عمل <code>quarantine</code> اکنون فایل را <strong>ایزوله</strong> می‌کند (کپی به قرنطینه + حذف از مسیر اصلی)، نه فقط کپی.
	</p>

	<?php if ( 0 === $count ) : ?>
		<div class="mvn-empty">مشکل بازی وجود ندارد. ابتدا یک اسکن اجرا کنید.</div>
	<?php else : ?>
		<div class="mvn-actions mvn-fix-actions" style="margin-bottom:16px">
			<button type="button" class="button button-primary mvn-fix-batch" id="mvn-fix-all" data-filter="" <?php disabled( $fixable <= 0 ); ?>>رفع همه (دسته‌ای)<?php echo $fixable > 0 ? ' (' . (int) $fixable . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-htaccess" data-filter="delete_htaccess" <?php disabled( empty( $ac['delete_htaccess'] ) ); ?>>حذف htaccess جعلی<?php echo ! empty( $ac['delete_htaccess'] ) ? ' (' . (int) $ac['delete_htaccess'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-clean" data-filter="clean" <?php disabled( empty( $ac['clean'] ) ); ?>>پاکسازی injection<?php echo ! empty( $ac['clean'] ) ? ' (' . (int) $ac['clean'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-uploads" data-filter="quarantine_delete" <?php disabled( empty( $ac['quarantine_delete'] ) ); ?>>حذف PHP uploads<?php echo ! empty( $ac['quarantine_delete'] ) ? ' (' . (int) $ac['quarantine_delete'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-core-file" data-filter="core_repair_file" <?php disabled( empty( $ac['core_repair_file'] ) ); ?>>تعمیر فایل هسته<?php echo ! empty( $ac['core_repair_file'] ) ? ' (' . (int) $ac['core_repair_file'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-core-extra" data-filter="delete_core_extra" <?php disabled( empty( $ac['delete_core_extra'] ) ); ?>>حذف فایل اضافی هسته<?php echo ! empty( $ac['delete_core_extra'] ) ? ' (' . (int) $ac['delete_core_extra'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-db-clean" data-filter="db_clean" <?php disabled( empty( $ac['db_clean'] ) ); ?>>پاکسازی DB<?php echo ! empty( $ac['db_clean'] ) ? ' (' . (int) $ac['db_clean'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-db-option" data-filter="db_delete_option" <?php disabled( empty( $ac['db_delete_option'] ) ); ?>>حذف option مشکوک<?php echo ! empty( $ac['db_delete_option'] ) ? ' (' . (int) $ac['db_delete_option'] . ')' : ''; ?></button>
			<button type="button" class="button mvn-fix-batch" id="mvn-fix-as-delete" data-filter="as_delete" <?php disabled( empty( $ac['as_delete'] ) ); ?>>حذف AS مشکوک<?php echo ! empty( $ac['as_delete'] ) ? ' (' . (int) $ac['as_delete'] . ')' : ''; ?></button>
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
				?>
				<tr data-id="<?php echo esc_attr( $iss['id'] ); ?>">
					<td class="mvn-conf-cell">
						<div class="mvn-conf-bar-wrap" title="<?php echo esc_attr( $conf . '% — ' . $conf_label ); ?>">
							<div class="mvn-conf-bar mvn-conf-<?php echo esc_attr( $conf_class ); ?>" style="width:<?php echo (int) $conf; ?>%"></div>
						</div>
						<span class="mvn-conf-num"><?php echo (int) $conf; ?>%</span>
						<small class="mvn-muted mvn-conf-label"><?php echo esc_html( $conf_label ); ?></small>
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
					<td><code><?php echo esc_html( isset( $iss['action'] ) ? $iss['action'] : '' ); ?></code></td>
					<td><pre class="mvn-snippet"><?php echo esc_html( isset( $iss['snippet'] ) ? $iss['snippet'] : '' ); ?></pre></td>
					<td class="mvn-actions-cell">
						<button type="button" class="button button-small mvn-fix-one" data-id="<?php echo esc_attr( $iss['id'] ); ?>">رفع</button>
						<button type="button" class="button button-small mvn-ignore-one" data-id="<?php echo esc_attr( $iss['id'] ); ?>" title="این مورد امن است و در اسکن‌های بعدی نادیده گرفته می‌شود">امن است</button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
