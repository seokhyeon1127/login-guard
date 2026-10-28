<?php
/**
 * Plugin Name:       로그인 가드 (Login Guard)
 * Plugin URI:        https://github.com/seokhyeon1127/login-guard
 * Description:       로그인 실패 횟수를 제한해 무차별 대입(brute-force) 공격을 막아주는 가벼운 보안 플러그인. 지정한 횟수(기본 5회) 이상 연속 실패하면 해당 IP의 로그인을 일정 시간(기본 10분) 차단합니다.
 * Version:           1.0.0
 * Requires at least: 5.0
 * Requires PHP:      7.2
 * Author:            고석현
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       login-guard
 *
 * 이 플러그인은 대학 오픈소스/DevOps 과제로 제작된 학생 프로젝트입니다.
 * 무보증(AS-IS)으로 제공되며, 가급적 테스트 사이트에서 사용해 주세요.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'LGUARD_VERSION', '1.0.0' );
define( 'LGUARD_LOG_TABLE', 'lguard_log' );

/* ------------------------------------------------------------------ *
 *  활성화 / 비활성화
 * ------------------------------------------------------------------ */
function lguard_activate() {
	add_option( 'lguard_max_attempts', 5 );     // 허용 실패 횟수
	add_option( 'lguard_lockout_minutes', 10 ); // 잠금 시간(분)
	add_option( 'lguard_enabled', 1 );          // 사용 여부

	global $wpdb;
	$table   = $wpdb->prefix . LGUARD_LOG_TABLE;
	$charset = $wpdb->get_charset_collate();
	$sql = "CREATE TABLE $table (
		id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
		event_time DATETIME NOT NULL,
		event_type VARCHAR(30) NOT NULL,
		ip VARCHAR(45) NOT NULL,
		username VARCHAR(100) NULL,
		detail VARCHAR(191) NULL,
		PRIMARY KEY (id)
	) $charset;";
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	dbDelta( $sql );
}
register_activation_hook( __FILE__, 'lguard_activate' );

/* ------------------------------------------------------------------ *
 *  공통 유틸
 * ------------------------------------------------------------------ */
function lguard_client_ip() {
	// 기본은 REMOTE_ADDR(가장 신뢰 가능). 프록시 뒤라면 서버 환경에 맞게 조정 필요.
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '0.0.0.0';
	return substr( sanitize_text_field( $ip ), 0, 45 );
}
function lguard_fail_key() { return 'lguard_f_' . md5( lguard_client_ip() ); }
function lguard_lock_key() { return 'lguard_l_' . md5( lguard_client_ip() ); }

function lguard_log( $type, $username = '', $detail = '' ) {
	global $wpdb;
	$wpdb->insert(
		$wpdb->prefix . LGUARD_LOG_TABLE,
		array(
			'event_time' => current_time( 'mysql' ),
			'event_type' => $type,
			'ip'         => lguard_client_ip(),
			'username'   => substr( (string) $username, 0, 100 ),
			'detail'     => substr( (string) $detail, 0, 191 ),
		),
		array( '%s', '%s', '%s', '%s', '%s' )
	);
}

/* ------------------------------------------------------------------ *
 *  핵심 방어 로직 (훅 기반)
 * ------------------------------------------------------------------ */

/** 인증 직전: 잠겨 있으면 로그인 차단 */
function lguard_check_lock( $user, $username, $password ) {
	if ( ! get_option( 'lguard_enabled', 1 ) || empty( $username ) ) {
		return $user;
	}
	$until = get_transient( lguard_lock_key() );
	if ( $until && $until > time() ) {
		$remain = (int) ceil( ( $until - time() ) / 60 );
		lguard_log( 'blocked', $username, "잠금 중 시도 차단 (약 {$remain}분 남음)" );
		return new WP_Error(
			'lguard_locked',
			sprintf(
				/* translators: %d = 남은 분 */
				'<strong>로그인 차단</strong><br>로그인 실패가 많아 약 %d분간 로그인이 제한되었습니다. 잠시 후 다시 시도해 주세요.',
				$remain
			)
		);
	}
	return $user;
}
add_filter( 'authenticate', 'lguard_check_lock', 30, 3 );

/** 로그인 실패마다: 횟수 증가, 임계치 도달 시 잠금 */
function lguard_on_failed( $username ) {
	if ( ! get_option( 'lguard_enabled', 1 ) ) { return; }
	$max      = (int) get_option( 'lguard_max_attempts', 5 );
	$lock_sec = (int) get_option( 'lguard_lockout_minutes', 10 ) * 60;

	if ( get_transient( lguard_lock_key() ) ) { return; } // 이미 잠김

	$count = (int) get_transient( lguard_fail_key() ) + 1;
	set_transient( lguard_fail_key(), $count, $lock_sec );
	lguard_log( 'failed', $username, "실패 {$count}/{$max}회" );

	if ( $count >= $max ) {
		set_transient( lguard_lock_key(), time() + $lock_sec, $lock_sec );
		lguard_log( 'lockout', $username, "{$max}회 연속 실패 → {$lock_sec}초 잠금" );
	}
}
add_action( 'wp_login_failed', 'lguard_on_failed', 10, 1 );

/** 로그인 성공 시: 카운트/잠금 해제 */
function lguard_on_success( $user_login, $user ) {
	delete_transient( lguard_fail_key() );
	delete_transient( lguard_lock_key() );
}
add_action( 'wp_login', 'lguard_on_success', 10, 2 );

/* ------------------------------------------------------------------ *
 *  관리자 화면 (설정 + 로그)
 * ------------------------------------------------------------------ */
function lguard_menu() {
	add_menu_page(
		'로그인 가드', '로그인 가드', 'manage_options',
		'login-guard', 'lguard_render_page', 'dashicons-shield', 80
	);
}
add_action( 'admin_menu', 'lguard_menu' );

function lguard_register_settings() {
	register_setting( 'lguard_group', 'lguard_enabled', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
	register_setting( 'lguard_group', 'lguard_max_attempts', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
	register_setting( 'lguard_group', 'lguard_lockout_minutes', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
}
add_action( 'admin_init', 'lguard_register_settings' );

function lguard_render_page() {
	if ( ! current_user_can( 'manage_options' ) ) { return; }
	global $wpdb;
	$table = $wpdb->prefix . LGUARD_LOG_TABLE;
	$rows  = $wpdb->get_results( "SELECT * FROM $table ORDER BY id DESC LIMIT 100" );
	$on    = (int) get_option( 'lguard_enabled', 1 );
	$max   = (int) get_option( 'lguard_max_attempts', 5 );
	$min   = (int) get_option( 'lguard_lockout_minutes', 10 );
	?>
	<div class="wrap">
		<h1>🛡 로그인 가드 <span style="font-size:13px;color:#888">v<?php echo esc_html( LGUARD_VERSION ); ?></span></h1>
		<p>로그인 실패 횟수를 제한해 무차별 대입 공격을 막습니다.</p>

		<h2>설정</h2>
		<form method="post" action="options.php">
			<?php settings_fields( 'lguard_group' ); ?>
			<table class="form-table">
				<tr><th>사용</th><td><label><input type="checkbox" name="lguard_enabled" value="1" <?php checked( $on, 1 ); ?>> 로그인 보호 사용</label></td></tr>
				<tr><th>허용 실패 횟수</th><td><input type="number" min="1" name="lguard_max_attempts" value="<?php echo esc_attr( $max ); ?>"> 회</td></tr>
				<tr><th>잠금 시간</th><td><input type="number" min="1" name="lguard_lockout_minutes" value="<?php echo esc_attr( $min ); ?>"> 분</td></tr>
			</table>
			<?php submit_button(); ?>
		</form>

		<h2>보안 로그 (최근 100건)</h2>
		<table class="widefat striped">
			<thead><tr><th>시각</th><th>유형</th><th>IP</th><th>사용자</th><th>상세</th></tr></thead>
			<tbody>
			<?php if ( empty( $rows ) ) : ?>
				<tr><td colspan="5">아직 기록이 없습니다.</td></tr>
			<?php else : foreach ( $rows as $r ) :
				$c = in_array( $r->event_type, array( 'lockout', 'blocked' ), true ) ? '#c0392b' : '#555'; ?>
				<tr>
					<td><?php echo esc_html( $r->event_time ); ?></td>
					<td style="color:<?php echo esc_attr( $c ); ?>;font-weight:600"><?php echo esc_html( $r->event_type ); ?></td>
					<td><?php echo esc_html( $r->ip ); ?></td>
					<td><?php echo esc_html( $r->username ); ?></td>
					<td><?php echo esc_html( $r->detail ); ?></td>
				</tr>
			<?php endforeach; endif; ?>
			</tbody>
		</table>
	</div>
	<?php
}
