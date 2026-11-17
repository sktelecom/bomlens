---
description: BomLens Windows 설치 파일의 코드 서명 정책(Code signing policy), 서명 요청을 승인하는 팀 구성, BomLens가 네트워크로 보내는 정보를 설명합니다.
---

# 코드 서명 정책 (Code signing policy)

Free code signing provided by SignPath.io, certificate by SignPath Foundation

Windows 설치 파일의 릴리스는 아래 정책에 따라 서명합니다. 서명하는 파일은 `BomLens-Setup.exe`입니다. 릴리스는 이 저장소에서 GitHub 호스티드 러너로 실행되는 워크플로로 빌드하며, 서명 요청마다 승인자가 직접 승인한 뒤에 파일에 서명합니다.

## 팀 역할

- Committers and reviewers: [fritzprix](https://github.com/fritzprix), [haksungjang](https://github.com/haksungjang), [SKDEVOCEAN](https://github.com/SKDEVOCEAN)
- Approvers: [haksungjang](https://github.com/haksungjang)

Committers는 별도 검토 없이 소스를 바꿀 수 있습니다. Committer가 아닌 사람이 제안한 변경은 팀원이 검토한 뒤에 병합합니다. Approvers는 릴리스마다 설치 파일에 서명할지 결정합니다.

## 개인정보 정책

BomLens는 사용자의 컴퓨터에서 실행됩니다. BomLens의 어떤 기능도 소스 코드, SBOM, 스캔 결과를 이 프로젝트가 운영하는 서버로 보내지 않으며, 텔레메트리나 사용 통계 수집도 없습니다. 스캐너 컨테이너는 지정한 대상만 읽고, 결과는 지정한 폴더에 씁니다.

다만 BomLens는 아래에 나열한 다른 서비스에 접속합니다. 요청에 식별자가 담기는 경우에는 어떤 식별자인지 함께 적었습니다.

### 기본으로 일어나는 요청

- 업데이트 확인(데스크톱 앱): 설치된 데스크톱 앱은 시작할 때 GitHub releases API(`api.github.com`)에 최신 릴리스를 물어 버전 번호를 비교합니다. 요청에는 사용자나 스캔에 관한 정보가 담기지 않습니다. GitHub는 이 요청을 다른 웹 요청과 똑같이 받으므로 IP 주소는 볼 수 있습니다. 요청이 실패해도 무시하며, 설치된 앱에는 이 확인을 끄는 설정이 없습니다.
- 스캐너 이미지: 처음 한 번 `ghcr.io`에서 내려받고, 이미 있는 이미지는 백그라운드에서 새로 고칩니다. 소스 스캔은 필요한 언어 이미지도 `ghcr.io`에서 받습니다. `SBOM_PULL=never`로 내려받기를 막고, `SBOM_IMAGE_TAR`로 파일에서 이미지를 설치할 수 있습니다.
- 취약점 데이터베이스: 보안 보고서는 Trivy를 쓰며, Trivy는 스캔 중 취약점 데이터베이스(약 1.5 GB)를 내려받아 캐시 폴더(`SBOM_TRIVY_CACHE`)에 둡니다. 데이터베이스와 대조하는 일은 컨테이너 안에서 이뤄집니다. `TRIVY_SKIP_DB_UPDATE=true`와 마운트한 데이터베이스로 오프라인 스캔을 할 수 있고, `TRIVY_DB_REPOSITORY`로 미러를 지정할 수 있습니다.
- 악용 신호: 보안 보고서는 찾은 CVE 식별자를 FIRST.org(EPSS)에 조회하고 CISA 악용 확인 취약점 목록(KEV)을 내려받습니다. 보내는 식별자는 발견된 항목의 CVE 식별자뿐입니다. `SECURITY_ENRICH=false`로 두 조회를 모두 끕니다.
- Go 취약점 데이터베이스: 이미지에 스냅숏이 들어 있습니다. 스냅숏이 7일보다 오래됐고 스캔이 오프라인이 아닐 때만 `vuln.go.dev`에서 새 것을 내려받습니다(`BOMLENS_GO_VULNDB_MAX_AGE_DAYS`).
- 소스 스캔의 의존성 해석: 소스 프로젝트의 의존성을 해석하고 crate 라이선스를 읽을 때 스캔 컨테이너가 프로젝트가 이미 쓰는 패키지 레지스트리에 패키지와 메타데이터를 요청합니다. `FETCH_LICENSE=false`로 라이선스 조회를 끄고, `--detection static`으로 빌드 대신 lock 파일을 읽게 할 수 있습니다.
- 웹 UI 조회: 웹 UI와 데스크톱 앱의 CVE·패키지 조회 화면은 사용할 때 OSV.dev에 묻습니다. 입력한 권고 식별자나 생태계, 패키지 이름, 버전을 보냅니다. `EXTERNAL_LOOKUP=false`로 끕니다.

### 기능을 켰을 때만 일어나는 요청

- `--license-registry`와 `STALENESS_ENRICH=true`는 컴포넌트의 생태계, 이름, 버전을 deps.dev에 보냅니다.
- `--resolve-purl`은 제출한 SBOM에서 찾은 패키지 식별자를 확인하려고 deps.dev에 보냅니다. `PURL_RESOLVE_IGNORE`에 적은 네임스페이스는 제외합니다.
- `--identify-vendored`는 C·C++ 소스 파일의 지문(해시)을 SCANOSS OSSKB 서비스에 보냅니다. 파일 자체는 보내지 않습니다. `SCANOSS_API_URL`로 다른 엔드포인트를 지정할 수 있습니다.
- `--model <owner/name>`과 `--resolve-models`는 Hugging Face 허브에서 모델 메타데이터를 읽고, Figshare 항목을 준 `--model`은 Figshare API에서 항목을 읽습니다. 웹 UI는 소스 스캔용으로 입력한 저장소 주소를 복제합니다.
- `--upload-target`, `--trusca`와 웹 UI의 외부 전송 단계는 완성된 SBOM을 사용자가 `API_URL`로 지정한 Dependency-Track 또는 TRUSCA 서버로 보냅니다.
- `--deep-cve`, `--deep-license` 같은 선택 이미지는 `ghcr.io`에서 내려받습니다. `SECURITY_NVD_VERIFY=true`는 NVD API도 조회합니다.

전체 옵션은 [CLI 레퍼런스](cli.ko.md)에, 설계 배경은 [로컬 우선 설계](../concepts/local-first.ko.md)에 있습니다.

## 설치와 제거

Windows 설치 프로그램은 설치 폴더를 고르게 합니다. 저장소에는 별도로 정의한 설치 단계가 없어서 BomLens가 방화벽이나 레지스트리를 직접 바꾸지 않습니다. BomLens를 제거하려면 Windows 설정에서 앱을 제거하고, 앱이 남긴 데이터까지 지우려면 설정 폴더 `%APPDATA%\sbom-generator-desktop`을 삭제합니다. 스캐너 이미지는 직접 지우기 전까지 Docker에 남습니다. 명령은 [비개발자 빠른 시작](../start/no-cli.ko.md)의 제거 절차를 참고하세요.
