<?php
/**
 * Plugin Name:       로그인 가드 (Login Guard)
 * Plugin URI:        https://github.com/seokhyeon1127/login-guard
 * Description:       최근 WordPress 공격 흐름에 맞춰, 플러그인 레벨에서 할 수 있는 보안 하드닝을 한곳에 모은 가벼운 플러그인입니다. 무차별 대입 차단(로그인 횟수 제한), 사용자명 열거 방지(로그인 오류 일반화·작성자/REST 스캔 차단), XML-RPC 비활성화, 보안 HTTP 헤더, 버전 정보 숨김, 대시보드 파일 편집 비활성화를 토글로 제공합니다.
 * Version:           1.2.0
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

define( 'LGUARD_VERSION', '1.2.0' );
define( 'LGUARD_LOG_TABLE', 'lguard_log' );

/* ------------------------------------------------------------------ *
 *  활성화 / 비활성화
 * ------------------------------------------------------------------ */
function lguard_activate() {
	add_option( 'lguard_max_attempts', 5 );     // 허용 실패 횟수
	add_option( 'lguard_lockout_minutes', 10 ); // 잠금 시간(분)
	add_option( 'lguard_enabled', 1 );          // 사용 여부
	add_option( 'lguard_hide_users', 1 );       // v1.1: 사용자명 열거 방지 사용 여부
	add_option( 'lguard_disable_xmlrpc', 1 );   // v1.2: XML-RPC 비활성화
	add_option( 'lguard_security_headers', 1 ); // v1.2: 보안 HTTP 헤더
	add_option( 'lguard_hide_version', 1 );     // v1.2: WordPress 버전 정보 숨김
	add_option( 'lguard_disable_file_edit', 1 );// v1.2: 대시보드 파일 편집 비활성화

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
 *  v1.1 추가: 사용자명 열거 방지 (Username Enumeration Protection)
 *  사용자 피드백("보안 말고는 별다른 차이가 없는듯")을 반영한 보안 기능.
 * ------------------------------------------------------------------ */

/**
 * 로그인 실패 메시지를 일반화한다.
 * 기본 WordPress는 "잘못된 아이디" vs "비밀번호 오류"를 구분해서 보여줘,
 * 공격자가 "이 아이디는 존재한다"는 사실을 알아낼 수 있다(사용자 열거).
 * → 하나의 일반 메시지로 통일해 아이디 존재 여부를 숨긴다.
 * (단, '로그인 가드'의 잠금 안내 메시지는 그대로 둔다.)
 */
function lguard_generic_login_error( $error ) {
	if ( ! get_option( 'lguard_hide_users', 1 ) ) { return $error; }
	if ( is_string( $error ) &&
	     ( strpos( $error, '로그인 차단' ) !== false || strpos( $error, '로그인이 제한' ) !== false ) ) {
		return $error; // 잠금 안내는 유지
	}
	return '<strong>로그인 실패</strong><br>아이디 또는 비밀번호가 올바르지 않습니다.';
}
add_filter( 'login_errors', 'lguard_generic_login_error' );

/**
 * 작성자 스캔(?author=N) 차단.
 * ?author=1 처럼 숫자를 넣으면 WordPress가 그 작성자의 글 목록으로 보내면서
 * URL에 작성자 아이디(slug)를 노출한다 → 공격자가 유효 아이디를 수집(열거)한다.
 * → 비로그인/프런트 요청에서 숫자 author 쿼리를 홈으로 돌려보내 차단한다.
 */
function lguard_block_author_scan() {
	if ( ! get_option( 'lguard_hide_users', 1 ) || is_admin() ) { return; }
	if ( isset( $_GET['author'] ) && preg_match( '/^\d+$/', (string) wp_unslash( $_GET['author'] ) ) ) {
		lguard_log( 'enum_block', '', '사용자명 열거 시도 차단 (?author=' . intval( $_GET['author'] ) . ')' );
		wp_safe_redirect( home_url( '/' ), 302 );
		exit;
	}
}
add_action( 'init', 'lguard_block_author_scan' );

/**
 * REST API 사용자 열거 차단.
 * 비로그인 상태에서 /wp-json/wp/v2/users 로 전체 사용자(아이디/슬러그)를
 * 긁어가는 것을 막는다. (작성자 스캔과 함께 열거 경로를 모두 닫는다)
 */
function lguard_block_rest_user_enum( $result, $server, $request ) {
	if ( ! get_option( 'lguard_hide_users', 1 ) ) { return $result; }
	if ( ! empty( $result ) ) { return $result; }
	if ( is_object( $request ) && ! is_user_logged_in() ) {
		$route = $request->get_route();
		if ( preg_match( '#^/wp/v2/users#', (string) $route ) ) {
			lguard_log( 'enum_block', '(비로그인)', 'REST 사용자 열거 차단 (' . $route . ')' );
			return new WP_Error( 'lguard_rest_forbidden', '로그인 후 이용할 수 있습니다.', array( 'status' => 401 ) );
		}
	}
	return $result;
}
add_filter( 'rest_pre_dispatch', 'lguard_block_rest_user_enum', 10, 3 );

/* ------------------------------------------------------------------ *
 *  v1.2 추가: 보안 하드닝 모음 (Security Hardening)
 *  사용자 피드백("기능이 너무 적어 아쉬웠다")을 반영해, 최근 WordPress 공격
 *  흐름(무차별 대입·열거·XML-RPC·핑거프린팅)에 맞춘 하드닝을 추가.
 *  각 항목은 설정에서 켜고 끌 수 있다.
 * ------------------------------------------------------------------ */

/** (1) XML-RPC 비활성화 — 무차별 대입 증폭·pingback 공격에 악용되는 통로를 막는다. */
if ( get_option( 'lguard_disable_xmlrpc', 1 ) ) {
	add_filter( 'xmlrpc_enabled', '__return_false' );
}

/** (2) 보안 HTTP 헤더 — 클릭재킹/MIME 스니핑 등 흔한 브라우저 측 공격을 줄인다. */
function lguard_security_headers() {
	if ( ! get_option( 'lguard_security_headers', 1 ) ) { return; }
	if ( headers_sent() ) { return; }
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
}
add_action( 'send_headers', 'lguard_security_headers' );

/** (3) WordPress 버전 정보 숨김 — 공격자의 버전 핑거프린팅을 어렵게 한다. */
if ( get_option( 'lguard_hide_version', 1 ) ) {
	remove_action( 'wp_head', 'wp_generator' );
	add_filter( 'the_generator', '__return_empty_string' );
	$lguard_strip_ver = function ( $src ) {
		if ( $src && strpos( $src, 'ver=' ) !== false ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	};
	add_filter( 'style_loader_src', $lguard_strip_ver, 9999 );
	add_filter( 'script_loader_src', $lguard_strip_ver, 9999 );
}

/** (4) 대시보드 파일 편집 비활성화 — 관리자 계정 탈취 시 코드 변조를 막는다. */
if ( get_option( 'lguard_disable_file_edit', 1 ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
	define( 'DISALLOW_FILE_EDIT', true );
}

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
	register_setting( 'lguard_group', 'lguard_hide_users', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
	register_setting( 'lguard_group', 'lguard_disable_xmlrpc', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
	register_setting( 'lguard_group', 'lguard_security_headers', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
	register_setting( 'lguard_group', 'lguard_hide_version', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
	register_setting( 'lguard_group', 'lguard_disable_file_edit', array( 'type' => 'integer', 'sanitize_callback' => 'absint' ) );
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
	$hide  = (int) get_option( 'lguard_hide_users', 1 );
	$xrpc  = (int) get_option( 'lguard_disable_xmlrpc', 1 );
	$hdr   = (int) get_option( 'lguard_security_headers', 1 );
	$ver   = (int) get_option( 'lguard_hide_version', 1 );
	$fedit = (int) get_option( 'lguard_disable_file_edit', 1 );
	?>
	<div class="wrap">
		<h1>🛡 로그인 가드 <span style="font-size:13px;color:#888">v<?php echo esc_html( LGUARD_VERSION ); ?></span></h1>
		<p>최근 WordPress 공격 흐름에 맞춰, 플러그인에서 할 수 있는 보안 하드닝을 한곳에 모았습니다. 각 항목을 켜고 끌 수 있어요.</p>

		<h2>설정</h2>
		<form method="post" action="options.php">
			<?php settings_fields( 'lguard_group' ); ?>

			<h3 style="margin-bottom:0">① 로그인 보호</h3>
			<table class="form-table">
				<tr><th>로그인 횟수 제한</th><td>
					<input type="hidden" name="lguard_enabled" value="0">
					<label><input type="checkbox" name="lguard_enabled" value="1" <?php checked( $on, 1 ); ?>> 사용 (무차별 대입 차단)</label></td></tr>
				<tr><th>허용 실패 횟수</th><td><input type="number" min="1" name="lguard_max_attempts" value="<?php echo esc_attr( $max ); ?>"> 회</td></tr>
				<tr><th>잠금 시간</th><td><input type="number" min="1" name="lguard_lockout_minutes" value="<?php echo esc_attr( $min ); ?>"> 분</td></tr>
			</table>

			<h3 style="margin-bottom:0">② 추가 하드닝</h3>
			<table class="form-table">
				<tr><th>사용자명 열거 방지</th><td>
					<input type="hidden" name="lguard_hide_users" value="0">
					<label><input type="checkbox" name="lguard_hide_users" value="1" <?php checked( $hide, 1 ); ?>> 사용</label>
					<p class="description">로그인 오류 메시지 일반화 + 작성자(?author=N)·REST(/wp-json/.../users) 스캔 차단</p></td></tr>
				<tr><th>XML-RPC 비활성화</th><td>
					<input type="hidden" name="lguard_disable_xmlrpc" value="0">
					<label><input type="checkbox" name="lguard_disable_xmlrpc" value="1" <?php checked( $xrpc, 1 ); ?>> 사용</label>
					<p class="description">무차별 대입 증폭·pingback 악용 통로 차단. (Jetpack·워드프레스 모바일 앱을 쓴다면 끄세요)</p></td></tr>
				<tr><th>보안 HTTP 헤더</th><td>
					<input type="hidden" name="lguard_security_headers" value="0">
					<label><input type="checkbox" name="lguard_security_headers" value="1" <?php checked( $hdr, 1 ); ?>> 사용</label>
					<p class="description">X-Frame-Options·X-Content-Type-Options·Referrer-Policy 추가 (클릭재킹·MIME 스니핑 방지)</p></td></tr>
				<tr><th>버전 정보 숨김</th><td>
					<input type="hidden" name="lguard_hide_version" value="0">
					<label><input type="checkbox" name="lguard_hide_version" value="1" <?php checked( $ver, 1 ); ?>> 사용</label>
					<p class="description">WordPress 버전 노출(generator·ver=) 제거로 핑거프린팅 축소</p></td></tr>
				<tr><th>파일 편집 비활성화</th><td>
					<input type="hidden" name="lguard_disable_file_edit" value="0">
					<label><input type="checkbox" name="lguard_disable_file_edit" value="1" <?php checked( $fedit, 1 ); ?>> 사용</label>
					<p class="description">대시보드의 플러그인/테마 코드 편집기 비활성화 (관리자 탈취 시 코드 변조 방지)</p></td></tr>
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
