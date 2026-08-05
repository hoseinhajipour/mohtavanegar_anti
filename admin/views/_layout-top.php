<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap mvn-wrap" dir="rtl">
	<div class="mvn-header">
		<div class="mvn-brand">
			<span class="mvn-logo dashicons dashicons-shield"></span>
			<div>
				<h1>آنتی‌ویروس محتوانگار</h1>
				<p class="mvn-sub">اسکن · رفع · تعمیر هسته · سخت‌سازی امنیتی</p>
			</div>
		</div>
		<nav class="mvn-tabs">
			<?php
			$tabs = array(
				'mvn-antivirus'  => 'داشبورد',
				'mvn-scan'       => 'اسکن',
				'mvn-fix'        => 'رفع مشکلات',
				'mvn-repair'     => 'تعمیر هسته',
				'mvn-hardening'  => 'سخت‌سازی',
				'mvn-quarantine' => 'قرنطینه',
			);
			$current = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'mvn-antivirus'; // phpcs:ignore
			foreach ( $tabs as $slug => $label ) :
				$class = ( $current === $slug ) ? 'is-active' : '';
				?>
				<a class="mvn-tab <?php echo esc_attr( $class ); ?>" href="<?php echo esc_url( admin_url( 'admin.php?page=' . $slug ) ); ?>"><?php echo esc_html( $label ); ?></a>
			<?php endforeach; ?>
		</nav>
	</div>
	<div class="mvn-body">
