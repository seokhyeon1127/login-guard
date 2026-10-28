=== 로그인 가드 (Login Guard) ===
Contributors: koseokhyeon
Tags: login, security, brute force, login attempts, lockout
Requires at least: 5.0
Tested up to: 6.5
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

로그인 실패 횟수를 제한해 무차별 대입(brute-force) 공격을 막아주는 가벼운 보안 플러그인입니다.

== Description ==

로그인 가드는 WordPress 로그인 창을 노리는 무차별 대입 공격을 막습니다.
지정한 횟수(기본 5회) 이상 연속으로 로그인에 실패하면, 해당 IP의 로그인을
일정 시간(기본 10분) 동안 차단합니다.

* 설정에서 허용 실패 횟수와 잠금 시간을 조절할 수 있습니다.
* 로그인 실패/잠금/차단 이벤트를 관리자 화면의 "보안 로그"에서 확인할 수 있습니다.
* 삭제 시 옵션과 로그 테이블을 깨끗이 정리합니다.

> 본 플러그인은 대학 오픈소스/DevOps 과제로 만든 학생 프로젝트이며, 무보증(AS-IS)으로
> 제공됩니다. 가급적 테스트 사이트에서 먼저 사용해 주세요. 피드백 대환영입니다!

== Installation ==

1. 플러그인 zip을 WordPress 관리자 → 플러그인 → 새로 추가 → 플러그인 업로드에서 올립니다.
2. 활성화합니다.
3. 왼쪽 메뉴의 "로그인 가드"에서 횟수/시간을 설정합니다.

== Frequently Asked Questions ==

= 잠금에 걸리면 어떻게 푸나요? =
설정한 잠금 시간이 지나면 자동으로 풀립니다. 정상적으로 로그인에 성공하면 즉시 해제됩니다.

= IP는 어떻게 식별하나요? =
기본적으로 서버의 REMOTE_ADDR를 사용합니다. 리버스 프록시/CDN 뒤에 있는 환경은
실제 IP 식별 방식이 다를 수 있습니다(향후 버전에서 옵션 제공 예정).

== Changelog ==

= 1.0.0 =
* 최초 공개: 로그인 실패 횟수 제한 + IP 잠금 + 보안 로그 + 설정 화면.
