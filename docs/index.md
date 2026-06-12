---
hide:
  - toc
---

# BomLens

SaaS 없이 로컬에서 단일 프로젝트의 SBOM(CycloneDX 1.6)을 생성하고 오픈소스 리스크를 평가하는 도구입니다. 소스 코드나 컨테이너 이미지, 바이너리, 받은 SBOM에서 SBOM과 오픈소스 고지문, 보안 위험 보고서를 한 번에 만듭니다.

[Windows용 내려받기 (.exe)](https://github.com/sktelecom/sbom-tools/releases/latest/download/SBOM-Generator-Setup.exe){ .md-button .md-button--primary }
[시작하기](getting-started.md){ .md-button }

명령줄이 부담스럽다면 위 설치 파일을 받아 더블클릭하세요. 단계별 안내는 [비개발자 빠른 시작](quickstart-no-cli.md)에 있습니다. Docker 엔진이 필요하며, Windows에서는 무료 [Rancher Desktop](https://rancherdesktop.io/)이 잘 맞습니다.

## 무엇부터 볼까

<div class="grid cards" markdown>

-   :material-rocket-launch: __시작하기__

    설치부터 첫 SBOM 생성까지 (웹 UI와 CLI).

    [:octicons-arrow-right-24: 시작하기](getting-started.md)

-   :material-cursor-default-click: __비개발자 빠른 시작__

    명령줄 없이 데스크톱 앱으로 SBOM과 고지문 만들기.

    [:octicons-arrow-right-24: 빠른 시작](quickstart-no-cli.md)

-   :material-format-list-bulleted: __입력 시나리오__

    GitHub URL, ZIP, 로컬 소스, 기존 SBOM, 펌웨어별 처리.

    [:octicons-arrow-right-24: 시나리오 가이드](scenarios-guide.md)

-   :material-file-document-check: __공급사 SBOM 검증__

    받은 SBOM의 요구사항 충족 검증과 위험 보고서 발행.

    [:octicons-arrow-right-24: 공급사 SBOM 검증](supplier-sbom-validation.md)

-   :material-cog: __사용 가이드__

    전체 옵션, 분석 모드, CI/CD 연동.

    [:octicons-arrow-right-24: 사용 가이드](usage-guide.md)

-   :material-shield-check: __고지문과 보안 보고서__

    산출물 생성과 해석, 웹 UI 사용법.

    [:octicons-arrow-right-24: 고지문·보안 보고서](notice-and-security.md)

</div>
