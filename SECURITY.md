# 보안 정책 (Security Policy)

> **English**: [SECURITY.en.md](SECURITY.en.md)

SBOM Generator는 소프트웨어 공급망 보안을 다루는 도구인 만큼, 도구 자체의 보안도
중요하게 여긴다. 취약점을 발견했다면 책임 있는 절차에 따라 알려 주기를 부탁한다.

## 지원 버전 (Supported Versions)

보안 수정은 최신 릴리스를 기준으로 제공한다. Docker 이미지는 `ghcr.io/sktelecom/sbom-generator:latest`
(이전 이름 별칭 `sbom-scanner:latest`) 태그가 최신 보안 패치를 반영한다.

| 버전 | 지원 여부 |
|------|-----------|
| 최신 릴리스 (`:latest`) | ✅ |
| 그 이전 버전 | ❌ |

오래된 버전을 쓰고 있다면 먼저 최신 릴리스로 올린 뒤 문제가 재현되는지 확인해
주기를 권한다.

## 취약점 신고 (Reporting a Vulnerability)

취약점은 **공개 이슈 트래커에 올리지 말고** 아래 두 경로 중 하나로 비공개로 알려
주기 바란다.

### 1. GitHub Private Vulnerability Reporting

이 저장소의 **Security** 탭에서 **Report a vulnerability** 를 눌러 비공개 보안
권고(advisory) 초안을 제출할 수 있다. 신고 내용은 유지보수자에게만 보이며, 수정과
공개 일정을 같은 자리에서 함께 다룰 수 있다.

### 2. 이메일

[opensource@sktelecom.com](mailto:opensource@sktelecom.com) 으로 보내도 된다.

### 신고에 담아 주면 좋은 정보

- 취약점 유형과 영향 범위
- 문제가 있는 파일 경로나 코드 위치
- 재현 단계 또는 개념 증명(PoC)
- 가능하다면 영향을 받는 버전과 환경(OS, Docker 버전)

## 처리 절차 (Process)

신고를 받으면 다음 흐름으로 대응한다. 자원봉사 기반 프로젝트인 만큼 아래 기한은
목표치이며 상황에 따라 달라질 수 있다.

- 영업일 기준 3일 이내에 접수를 확인한다.
- 검토 후 취약점 여부와 심각도를 판단해 신고자에게 알린다.
- 수정이 필요하면 패치를 준비하고, 신고자와 공개 시점을 조율한다.
- 수정이 배포되면 보안 권고를 공개하고, 원하는 경우 신고자를 기여자로 표기한다.

비공개 신고 내용은 수정과 조율이 끝나기 전까지 외부에 공유하지 않는다.
