# Windows 테스트 안내

Windows(Git for Windows + Docker Desktop 또는 Rancher Desktop)에서 BomLens의 docker
볼륨 마운트가 정상 동작하는지 검증하는 절차다. Git bash(MSYS)에서 `scan-sbom.sh`를
실행할 때 마운트 경로가 깨지던 문제와, 웹 UI가 sibling 컨테이너로 스캔을 넘길 때 호스트
경로를 잘못 넘기던 문제를 함께 확인한다.

macOS와 Linux에서는 이 절차가 필요 없다. 아래 검증은 Windows 고유 위험만 다룬다.

## 무엇이 고쳐졌나

두 갈래의 마운트 문제를 수정했다.

- CLI(Git bash 경유): `scripts/scan-sbom.sh`가 MSYS 환경을 감지해, docker 호출마다
  컨테이너 경로 변환을 끄고(`MSYS_NO_PATHCONV`) 호스트 마운트 소스를 `cygpath -m`으로
  `C:/...` 형태로 바꾼다. 이 처리는 macOS와 Linux에서 no-op이다.
- 웹 UI(sibling 컨테이너): `docker/web/server.py`가 호스트 경로를 정슬래시로 정규화하고,
  호스트 바인드 마운트 검사(`_HOSTPATH_RE`)가 Windows 드라이브 경로(`C:/...`)를
  통과시킨다. 웹 UI의 firmware/AI 스캔과 소스 스캔(cdxgen)은 마운트된 도커 소켓으로
  sibling 컨테이너를 띄우는데, 그 `-v` 소스가 호스트 데몬이 읽을 수 있는 드라이브
  경로여야 한다.

## 사전 준비

- Windows 11.
- Docker Desktop(WSL2 백엔드 권장) 또는 Rancher Desktop. 엔진이 실행 중이어야 한다.
- 파일 공유: 스캔 대상과 출력 폴더가 도커가 공유하는 드라이브에 있어야 한다. 홈 디렉토리
  트리(`%USERPROFILE%`)는 기본 공유라 그 아래에서 실행하면 안전하다. 공유 밖 경로면
  마운트가 비어 산출물이 호스트에 나타나지 않는다.
- Git for Windows(`bash.exe` 제공). CLI를 Git bash로 돌릴 때 필요하다.
- 이 저장소(sbom-tools)를 clone.

## 자동 스모크 테스트

`tests/windows-smoke.ps1`이 Windows 고유 위험을 헤드리스로 확인한다. PowerShell에서
저장소 루트를 기준으로 실행한다.

```
powershell -ExecutionPolicy Bypass -File tests\windows-smoke.ps1
```

각 단계가 확인하는 내용은 다음과 같다.

- Docker 엔진 점검과 스캐너 이미지 프리풀.
- CLI 스캔 e2e: `scan-sbom.bat`로 `examples\nodejs`를 SOURCE 스캔해 고지문(NOTICE)이
  호스트 폴더에 실제로 생성되는지 본다. 이 단계가 이번 CLI 마운트 수정의 핵심 회귀
  지점이다. 수정 전에는 stage 1에서 마운트가 깨져 산출물이 나오지 않았다.
- 웹 UI 헬스체크: UI 컨테이너가 떠서 `http://localhost:8080`이 200을 반환하는지, 그리고
  `/capabilities`의 `hostDir`가 드라이브 경로(`C:\...` 또는 `C:/...`)로 잡히는지 본다.
  `hostDir`가 비면 웹 UI의 sibling firmware/AI 스캔이 소스를 마운트하지 못한다.
- 비공유 경로 함정: 공유 밖 경로에서는 산출물이 나타나지 않고 오류로 잡히는지 확인한다.

자동화할 수 없는 단계는 SKIP으로 남는다. 실패가 하나라도 있으면 종료 코드 1이다.

기본 이미지는 `ghcr.io/sktelecom/bomlens:latest`이다. 다른 이미지를 쓰려면
`-Image` 인자나 `SBOM_SCANNER_IMAGE` 환경변수로 지정한다.

## 수동 검증

스모크 테스트가 다루지 않는 부분은 아래를 직접 확인한다. 모두 홈 디렉토리 아래
공유 경로에서 실행한다.

### CLI 스캔(Git bash 경유)

예제 디렉토리를 홈 아래로 복사한 뒤 각 모드를 돌려 산출물이 호스트에 생성되는지 본다.

- SOURCE: 예제 폴더에서 `scripts\scan-sbom.bat --project Demo --version 1.0.0 --generate-only`.
  언어별 예제(`examples\python`, `examples\nodejs`, `examples\go` 등)로 반복한다.
  `Demo_1.0.0\Demo_1.0.0_bom.json`과 부속 파일이 생기면 통과다.
- image: `scripts\scan-sbom.bat --project Img --version 1.0.0 <이미지참조> --generate-only`.
- firmware / AI: 해당 opt-in 이미지를 빌드했거나 받아둔 경우에만 확인한다.

수정 전 실패 증상은 다음과 같았다. 참고로만 둔다.

- `sh: /tmp/build-prep.sh: No such file or directory` (컨테이너 경로가 변환됨)
- `/tmp/build-prep.sh: Is a directory` (호스트 소스 `/c/...`를 못 읽어 빈 디렉토리를 붙임)
- 둘 다 `[ERROR] SBOM generation failed (stage 1)`로 끝났다.

### 웹 UI 스캔

웹 UI는 `scripts\sbom-ui.bat`을 더블클릭하거나 실행해 띄운다. 이 런처는 cmd에서 직접
docker를 호출하므로 바깥 컨테이너 실행에는 Git bash가 필요 없다. 결과는 기본으로
`%USERPROFILE%\sbom-output` 아래에 쌓인다.

브라우저에서 다음을 확인한다.

- 소스 스캔: 소스 압축 파일을 업로드해 스캔한다. 컴포넌트가 채워진 SBOM과 리포트가
  나오면, 웹 UI가 sibling cdxgen 컨테이너에 호스트 경로를 제대로 넘긴 것이다.
- firmware 업로드 스캔: firmware 이미지를 업로드해 스캔한다. 이 경로는 sibling firmware
  컨테이너를 띄우고 업로드 파일을 `/input`으로 마운트한다. 스캔이 시작돼 로그가 흐르고
  산출물이 나오면 통과다. 시작 직후 "sibling 컨테이너를 시작하지 못했습니다" 류의
  오류가 나면 호스트 경로 전달이 실패한 것이다.

## 문제 해결

- `No such file or directory`나 `Is a directory`로 stage 1이 실패: CLI 마운트 경로
  문제다. `scan-sbom.sh`에 이번 수정이 반영됐는지, `cygpath`가 PATH에 있는지(Git for
  Windows 기본 포함) 확인한다.
- `[ERROR] SBOM not found on host` / "container ran but no artifact reached this folder":
  출력 폴더가 도커 파일 공유 밖이다. 홈 디렉토리 아래 공유 경로에서 다시 실행한다.
- 웹 UI에서 firmware/AI 스캔이 sibling 시작 단계에서 실패, 또는 `/capabilities`의
  `hostDir`가 빔: `SBOM_UI_HOST_DIR` 전달 문제다. `sbom-ui.bat`으로 띄웠는지, 출력 폴더가
  드라이브 경로로 잡히는지 확인한다.

## 결과 보고

실패가 있으면 실행한 명령, 전체 로그, 재현 환경(OS, 도커 엔진과 버전, 이미지 태그,
입력 종류)을 함께 남긴다. 스모크 테스트 출력과 위 수동 검증 결과를 첨부하면 원인 분석이
빠르다.
