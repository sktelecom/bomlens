# 내부 문서 (메인테이너용)

이 폴더는 sbom-tools 메인테이너를 위한 의사결정과 조사 문서를 모아 둔 곳입니다. 도구를 사용하려는 분은 이 폴더가 아니라 [docs/](../) 상위의 사용자 가이드를 보세요.

아키텍처 문서는 사용자 문서 사이트로 옮겼습니다. [docs/architecture.md](../concepts/architecture.ko.md)를 보세요.

전략과 방향, 우선순위를 다루는 문서는 이 폴더가 아니라 별도 비공개 저장소에서 관리합니다. 이 폴더에는 기술 설계와 기여자 실무 문서만 둡니다.

| 문서 | 내용 |
|------|------|
| [공급사 제출 SBOM 검증·분석](supplier-sbom-analysis.md) | ANALYZE 모드 검증·변환·위험 보고 설계 |
| [검출 모드](detection-modes.md) | SOURCE 스캔에 경량·정적 검출 모드를 옵트인으로 더하는 설계(미구현 제안) |
| [펌웨어 분석](firmware-analysis.md) | FIRMWARE 모드 언팩·바이너리 식별 설계와 도구 선정 |
| [배포 절차](release-guide.md) | 태그 기반 릴리스 체크리스트와 실행 절차 |
| [도구 버전 업그레이드 안전장치](dependency-upgrade-policy.md) | 외부 도구 신규 버전 도입을 지키는 4계층(감지·스냅샷·정본·호환성 점검) |

> 사용자용 경량 가이드는 상위 [docs/](../)에 있습니다. 펌웨어는 [펌웨어 분석 가이드](../guides/firmware.ko.md), 공급사 SBOM 검증은 [공급사 SBOM 검증 가이드](../guides/supplier-sbom.ko.md)를 참고하세요.
