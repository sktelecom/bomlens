---
description: 다른 프로그램이 BomLens 스캔 엔진을 쿠버네티스에서 엔진 계약대로 실행하게 해 주는 Python 패키지입니다.
---

# 엔진 실행기

BomLens를 스캔 엔진으로 쓰는 프로그램은 [엔진 계약](engine-contract.ko.md)대로 엔진 컨테이너를 직접 실행할 수도 있고, 엔진 실행기를 호출할 수도 있습니다. 실행기는 Python 패키지(`bomlens-runner`, 표준 라이브러리만 사용, Python 3.10 이상)이며, 그런 프로그램마다 작성해야 했던 다음 일을 맡습니다.

- `MODE=PLAN`을 실행하고, 실행 계획을 읽어 허용 범위에 맞는지 검사합니다.
- 1단계와 2단계를 쿠버네티스 Job으로 실행하고, 1단계의 종료 코드, 메모리 부족 여부, 로그를 2단계에 넘기며, 1단계가 강제 종료되면 소스 복구 실행을 합니다.
- 결과 매니페스트와 거기 적힌 출력 파일을 검사합니다.
- 반환하기 전에 모든 Job과 Pod를 지웁니다.

각 릴리스의 실행기는 그 릴리스의 실행 계획과 매니페스트를 알고 있습니다. 그래서 실행기 버전만 올리면 프로그램 코드를 고치지 않아도 그 릴리스의 엔진 변경이 반영됩니다.

## 설치

패키지를 발행하기 전까지는 릴리스 태그에서 설치합니다.

```bash
pip install "git+https://github.com/sktelecom/bomlens@v1.15.0#subdirectory=runner"
```

`bomlens-runner` 명령은 JSON 정책 파일로 스캔 하나를 실행합니다. 프로그램에서는 패키지를 직접 호출합니다.

## 소스 스캔 실행

```python
from pathlib import Path
from bomlens_runner import Images, RunnerPolicy, Volume, run_source_scan
from bomlens_runner.kubernetes import KubeApi, KubernetesBackend, KubernetesOptions

policy = RunnerPolicy(
    images=Images.parse("ghcr.io/sktelecom/bomlens:1.15.0@sha256:563fb0be1b188bbd550f504fcd77b3f2f062637d25104c3f9ac99bcfd61f2a51"),
    workspace=Volume("pvc-workspace", Path("/workspace")),   # 클레임 이름과 이 프로세스에서 보이는 위치
    trivy_db=Volume("pvc-trivy", Path("/trivy")),
    uid=1000, gid=1000,
    labels={"example.com/app": "scanner"},
)
backend = KubernetesBackend(KubeApi.in_cluster(),
                            KubernetesOptions(namespace="scan", workspace_claim="pvc-workspace",
                                              trivy_db_claim="pvc-trivy"))
result = run_source_scan(policy, backend, scan_id="a1b2c3", project="app", version="1.0",
                         scan_dir=Path("/workspace/a1b2c3"), source=Path("/workspace/a1b2c3/src"),
                         on_log=lambda stage, line: print(stage, line))
print(result.manifest.run_status, result.output_dir)
```

`run_image_scan`은 이미지를 레지스트리에서 읽어 컨테이너 하나로 스캔합니다(`MODE=IMAGE`). root가 아닌 `uid`가 필요합니다. 두 함수 모두 `RunResult`를 돌려줍니다. 여기에는 출력 폴더, 검사를 마친 매니페스트(`EngineResult`), 실행 계획의 상태와 사유, 감지한 생태계, 컨테이너별 종료 코드와 시간 초과 및 메모리 부족 여부가 들어 있습니다(`as_metadata()`는 이를 사전으로 줍니다). 출력 파일은 `read_output`으로 읽습니다. 파일마다 크기와 sha256을 매니페스트와 대조하고 한 번만 읽습니다.

| 인자 | 뜻 |
|---|---|
| `scan_id` | 영문 소문자, 숫자, `-`로 된 1~32자. Job 이름과 라벨에 쓰이므로, 같은 id로 다시 호출하면 중단된 이전 실행이 남긴 것을 지웁니다 |
| `scan_dir` | 이 스캔에 쓸 작업 공간 아래 폴더. 실행기는 `scan_dir/bomlens/`에 파일을 두고 그 폴더를 새로 만듭니다 |
| `source` | 작업 공간 아래의 소스 트리 |
| `on_stage` | 각 단계 전에 `prep`, `cdxgen`, `postprocess`로 호출됩니다. 여기서 `ScanCancelled`를 던지면 스캔이 멈춥니다 |
| `on_log` | 컨테이너가 출력한 줄마다 `(stage, line)`으로 호출됩니다(64 KiB를 넘는 줄은 잘리고, 컨테이너당 16 MiB까지). 컨테이너 출력이 나가는 곳은 여기뿐이며, 예외 메시지에는 출력 줄이나 경로가 들어가지 않습니다 |
| `cancel` | 실행기가 주기적으로 확인하는 함수. 참을 돌려주면 실행 중인 컨테이너를 멈추고 지운 뒤 `ScanCancelled`를 던집니다 |

## 정책

실행기는 컨테이너에 넘길 값을 자기 프로세스 환경에서 읽지 않습니다. 컨테이너가 받는 값은 실행기가 정한 값, 검사한 실행 계획이 정한 값, 정책에 적혀 있고 그 컨테이너에 허용된 값 중 하나입니다.

| 필드 | 뜻 |
|---|---|
| `images` | 엔진 이미지와, 쓸 때는 `deep_license`, `deep_cve` 이미지. 각각 `repository:tag@sha256:...` 형식. `latest`와 다이제스트 없는 이미지는 거부합니다 |
| `workspace`, `trivy_db` | 클레임 이름과 이 프로세스에서 보이는 위치. 실행기가 마운트하는 경로는 모두 `workspace.local_root` 아래에 있어야 하고 심볼릭 링크를 거치면 안 됩니다 |
| `stage1_repositories`, `stage1_image_prefix` | 1단계 이미지를 받을 수 있는 곳(기본값 `ghcr.io/cdxgen/`). 미러 접두어를 주면 기본값 대신 그 접두어만 허용하고, `MODE=PLAN`에 `CDXGEN_IMAGE_PREFIX`로 넘깁니다 |
| `limits`, `timeouts` | 컨테이너별 메모리, CPU, `/tmp` 크기와, 컨테이너별 시간 제한 및 이미지 pull 시간 제한 |
| `uid`, `gid` | 실행 계획, 2단계, 이미지 스캔 컨테이너를 실행할 사용자이자, 1단계가 쓴 파일의 소유자(`HOST_UID`/`HOST_GID`). 실행기 자신의 사용자를 주세요. 실행기가 컨테이너용으로 쓰는 파일은 소유자만 읽을 수 있습니다 |
| `stage1_env`, `stage2_env`, `image_env` | 컨테이너별로 넘길 값. 실행기가 직접 정하는 이름이나 그 컨테이너가 받지 않는 이름은 거부합니다. 값으로 쿠버네티스 Secret 키를 가리키는 `SecretRef`를 주면 값이 Job에 적히지 않습니다. `NVD_API_KEY`, `TRIVY_USERNAME`, `TRIVY_PASSWORD`, `TRIVY_REGISTRY_TOKEN`, 사용자 이름이나 비밀번호가 들어간 프록시 주소는 이 방법으로만 받습니다 |
| `caller_mounts` | 실행 계획의 호출자 역할(`cache-maven`, `cache-gradle`, `maven-settings`와 그 밖의 설정 역할)에 마운트할 폴더나 파일 |
| `labels` | 모든 Job과 Pod에 붙일 라벨 |
| `stage2_network` | 2단계에 `egress` 라벨을 붙입니다. 네트워크가 필요한 조회를 켤 때 씁니다(기본값은 네트워크 없음) |
| `deep_license`, `deep_cve` | 2단계를 deep-license 또는 deep-cve 이미지로 실행합니다(둘을 함께 쓸 수는 없음) |

## 무엇을 검사하나

실행 계획에서는 다음을 거부합니다.

- 다른 계약 이름이나 주 버전
- `generate`, `postprocess` 순서가 아닌 단계
- 다이제스트로 고정되지 않았거나 허용 저장소 밖에 있는 1단계 이미지, 설정과 다른 2단계 이미지
- 모르는 마운트 역할이나 그 단계에 맞지 않는 역할
- 시스템 폴더, `/`, `/tmp`나 `/trivy-db` 아래(문서에 적은 예외 제외), `..`가 들어간 마운트 대상
- `bomlens-plan/` 밖의 계획 파일, 필수로 표시된 호출자 역할
- 숫자가 아닌 사용자, 셸이 아닌 진입점, 필수 값이 빠진 2단계 환경변수

허용 목록에 없는 환경변수 이름은 버리고 `RunResult.dropped_plan_env`에 남깁니다.

결과 매니페스트에서는 다음을 거부합니다.

- 심볼릭 링크이거나 4 MiB를 넘는 파일
- 다른 계약 이름이나 주 버전
- 모르는 실행 상태나 단계 상태
- 성공으로 기록됐는데 종료 코드가 0이 아닌 실행

출력 파일은 경로가 단순한 파일 이름이 아니거나, 256 MiB를 넘거나, 크기나 sha256이 매니페스트와 다르면 거부합니다. 모르는 단계 id, 사유, 역할은 그대로 둡니다.

## 쿠버네티스 준비

실행기는 Job만 만듭니다. 클러스터 쪽에서 준비할 것은 다음과 같습니다.

- 1단계를 허용하는 Pod Security 수준의 네임스페이스. 1단계는 의존성 해석기가 패키지를 설치하고 lock 파일을 쓰기 때문에 root(`0:0`)로 실행되며, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`를 가집니다. `baseline`은 이를 허용하고 `restricted`는 허용하지 않습니다. 나머지 컨테이너는 정책의 비root 사용자로 실행되고 capability를 모두 뺍니다.
- 실행기 서비스 계정의 Role: `jobs`(create, get, list, delete), `pods`(get, list, delete), `pods/log`(get)
- 작업 공간 클레임(실행기와 Job이 다른 노드에 놓일 수 있으면 `ReadWriteMany`)과 Trivy 데이터베이스 클레임
- 아래 라벨로 Pod를 고르는 NetworkPolicy. 실행기는 NetworkPolicy를 만들지 않으므로 그 권한이 필요 없습니다.

| 라벨 | 값 |
|---|---|
| `app.kubernetes.io/part-of` | `bomlens-engine` |
| `app.kubernetes.io/component` | `engine-plan`, `engine-stage1`, `engine-restore`, `engine-stage2`, `engine-image`, `engine-chown` |
| `bomlens.engine/network` | 1단계와 이미지 스캔(그리고 `stage2_network`를 켠 2단계)은 `egress`, 나머지는 `none` |
| `bomlens.engine/scan` | 스캔 id |

`bomlens.engine/network: none`에는 모든 통신을 막는 정책을, `egress`에는 DNS와 클러스터 사설 대역을 뺀 인터넷만 허용하는 정책을 걸면 CLI와 같은 네트워크 조건이 됩니다. NetworkPolicy를 실제로 적용하는 CNI가 필요합니다. 모든 Pod는 seccomp 프로필 `RuntimeDefault`, 서비스 계정 토큰 없음, 서비스 링크 없음, 읽기 전용 루트 파일시스템, `/tmp`의 `emptyDir`로 실행됩니다. 쿠버네티스에는 Pod 단위 프로세스 수 제한이 없으므로 `limits.pids`는 노드에 `podPidsLimit`이 설정된 경우에만 적용됩니다.

CI는 커밋에서 빌드한 이미지로 [kind](https://kind.sigs.k8s.io/) 클러스터에서 실행기를 돌립니다(`tests/test-engine-runner-kind.sh`). 소스 스캔, 취소한 스캔, 이미지 스캔, 그리고 위 두 정책 아래에서 네트워크 라벨이 동작하는지를 확인합니다.

## 버전

패키지 버전은 함께 나온 BomLens 릴리스의 버전과 같고, 그 릴리스의 이미지를 담고 있습니다. 명령에 `images`를 주지 않으면 이 이미지를 쓰고, 프로그램에서는 `release_images()`로 가져옵니다. 실행기는 자신이 만들어진 계약 주 버전(1)만 읽고 다른 주 버전은 거부합니다.
