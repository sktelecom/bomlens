# 내부 문서 (메인테이너용)

이 폴더는 sbom-tools 메인테이너를 위한 의사결정과 조사 문서를 모아 둔 곳입니다. 도구를 사용하려는 분은 이 폴더가 아니라 [docs/](../) 상위의 사용자 가이드를 보세요.

아키텍처 문서는 사용자 문서 사이트로 옮겼습니다. [docs/architecture.md](../concepts/architecture.ko.md)를 보세요.

| 문서 | 내용 |
|------|------|
| [방향성 조사 보고서](direction-study.md) | Docker 이미지의 가치(cdxgen 대비 측정)와 설계 방향 |
| [데스크톱 앱 검토 보고서](desktop-app-study.md) | Windows 데스크톱 앱(Electron) 도입 검토 |
| [공급사 제출 SBOM 검증·분석](supplier-sbom-analysis.md) | ANALYZE 모드 검증·변환·위험 보고 설계 |
| [펌웨어 분석](firmware-analysis.md) | FIRMWARE 모드 언팩·바이너리 식별 설계와 도구 선정 |
| [개선 로드맵](improvement-roadmap.md) | 스캔 결과에서 드러난 미비점과 우선순위 |
| [문서 사용성 검토 보고서](docs-usability-review.md) | 신규 사용자 관점의 README와 가이드 검토, 우선순위 개선안 |
| [외부 등록 채널](seo-external-listings.md) | 검색·AI 노출용 큐레이션 목록과 레지스트리 제출 자료 |
| [배포 절차](release-guide.md) | 태그 기반 릴리스 체크리스트와 실행 절차 |
| [도구 버전 업그레이드 안전장치](dependency-upgrade-policy.md) | 외부 도구 신규 버전 도입을 지키는 4계층(감지·스냅샷·정본·호환성 점검) |

> 사용자용 경량 가이드는 상위 [docs/](../)에 있습니다. 펌웨어는 [펌웨어 분석 가이드](../guides/firmware.ko.md), 공급사 SBOM 검증은 [공급사 SBOM 검증 가이드](../guides/supplier-sbom.ko.md)를 참고하세요.
