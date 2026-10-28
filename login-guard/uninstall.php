<?php
/**
 * 플러그인 삭제 시 정리 작업.
 * 옵션, 트랜지언트, 로그 테이블을 모두 제거해 흔적을 남기지 않습니다.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { exit; }

delete_option( 'lguard_enabled' );
delete_option( 'lguard_max_attempts' );
delete_option( 'lguard_lockout_minutes' );

global $wpdb;
// 남아있을 수 있는 트랜지언트 정리
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\_transient\_lguard\_%'
	    OR option_name LIKE '\_transient\_timeout\_lguard\_%'"
);
// 로그 테이블 제거
$table = $wpdb->prefix . 'lguard_log';
$wpdb->query( "DROP TABLE IF EXISTS $table" );
