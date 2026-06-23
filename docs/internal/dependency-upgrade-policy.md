# 도구 버전 업그레이드 안전장치 (메인테이너용)

이 문서는 BomLens가 의존하는 외부 오픈소스 도구(cdxgen·trivy·syft·scanoss·unblob·cve-bin-tool·scancode 등)의 신규 버전을 안전하게 도입하기 위한 체계를 정리한다. 도구를 사용하려는 분은 이 폴더가 아니라 [docs/](../) 상위의 사용자 가이드를 보세요.

## 왜 필요한가

BomLens는 여러 도구의 조합이고, 그 버전을 따라가는 것이 기본 운영이다. 그런데 도구 버전은 `docker/Dockerfile`의 ARG와 `docker/lib/source-detect.sh`의 셸 변수로 핀돼 있어 Dependabot이 인식하지 못한다(Dependabot은 npm·GitHub Actions·base Docker 이미지만 본다). 또한 기존 테스트는 출력이 CycloneDX인지 정도만 확인해, 도구를 올렸을 때 specVersion·컴포넌트·필드가 달라져도 조용히 통과한다. 이 두 빈틈을 메우기 위해 네 계층을 둔다.

## 네 계층

| 계층 | 무엇 | 어디 |
|---|---|---|
| 1. 신규 버전 감지 | Renovate가 도구 버전을 추적해 bump PR을 연다 | `renovate.json`, `.github/workflows/renovate.yml` |
| 2. 출력 회귀 스냅샷 | 후처리 출력을 golden과 비교해 변화가 diff로 드러난다 | `tests/test-snapshot.sh`, `tests/lib/snapshot-normalize.jq`, `tests/snapshots/` |
| 3. 단일 버전 소스 + 절차 | 버전 정본 일원화와 사람 검증 체크리스트 | `docker/Dockerfile`(ARG 정본), [배포 절차](release-guide.md) |
| 4. 주기적 호환성 점검 | 최신 cdxgen으로 예제를 미리 돌려 깨짐을 사전 경고 | `.github/workflows/upstream-compat.yml` |

### 계층 1 — 신규 버전 감지 (Renovate)

Dependabot이 못 보는 ARG·셸 변수 핀을 Renovate의 customManager 정규식으로 추적한다. `docker/Dockerfile`의 각 도구 ARG 위에 `# renovate: datasource=... depName=...` 주석을 달아 두면, Renovate가 업스트림 릴리스와 비교해 bump PR을 연다. cdxgen 이미지 태그(`source-detect.sh`의 `CDXGEN_TAG`·`CDXGEN_ALLINONE`)도 같은 방식으로 추적한다.

기존 Dependabot 설정과 겹치지 않도록 Renovate는 `enabledManagers: ["custom.regex"]`로 customManager만 켠다. npm·GitHub Actions·base Docker 이미지는 그대로 Dependabot이 담당한다.

실행에는 저장소/조직 시크릿 `RENOVATE_TOKEN`(PR 생성용 PAT, classic은 repo+workflow, fine-grained는 contents+pull-requests write)이 필요하다. 없으면 워크플로는 아무 일도 하지 않는다.

### 계층 2 — 출력 회귀 스냅샷

`tests/test-snapshot.sh`는 고정 입력 픽스처를 후처리 스크립트로 돌린 결과에서 휘발성 필드(타임스탬프·serialNumber·도구 버전)를 `tests/lib/snapshot-normalize.jq`로 걷어내고, `tests/snapshots/`의 golden과 비교한다. specVersion·컴포넌트·라이선스·cpe 같은 의미 있는 변화는 모두 diff로 드러난다. 매 PR에서 `ci.yml`의 후처리 잡이 실행한다(Docker 불필요).

의도된 변화로 출력이 바뀌면 golden을 다시 떠서 커밋한다.

```bash
UPDATE_SNAPSHOTS=1 bash tests/test-snapshot.sh
```

이 스냅샷은 우리 jq 파이프라인의 회귀를 잡는다. 도구 버전 자체가 출력을 바꾸는 드리프트는 계층 4가 같은 정규화 필터를 재사용해 잡는다.

### 계층 3 — 단일 버전 소스 + 절차

버전 정본은 `docker/Dockerfile`의 ARG다. `docker-publish.yml`은 이 값을 grep으로 읽어 쓰므로 워크플로에 같은 버전을 따로 적어 동기화할 필요가 없다.

도구를 올릴 때 따르는 사람 검증 절차는 [배포 절차](release-guide.md)의 "도구 버전 업그레이드"를 따른다.

### 계층 4 — 주기적 호환성 점검

`examples.yml`은 핀된 버전으로 돌아 다음 버전이 깨질지는 알려주지 못한다. `upstream-compat.yml`은 주간으로 최신 cdxgen을 당겨 대표 예제(python·nodejs·java-maven·go)를 스캔하고, 출력이 여전히 정상 CycloneDX이며 컴포넌트가 해소되는지 확인한다. 깨지면 `upstream-compat` 라벨로 추적 이슈를 자동으로 연다. cdxgen은 런타임에 당겨오므로 이동 태그(v12)에서도 드리프트가 생길 수 있어 이 점검이 의미가 있다. syft·trivy는 이미지에 ARG로 박히므로, 이들의 드리프트는 Renovate bump PR이 전체 CI(예제 스캔·스냅샷)를 돌리며 드러난다.

## 업그레이드 흐름

도구 신규 버전이 나오면 다음 순서로 처리한다.

1. Renovate가 bump PR을 연다(계층 1). 메이저는 `major-upgrade` 라벨로 분리된다.
2. PR에서 기존 CI가 돈다. 계층 2 스냅샷이 출력 변화를 diff로 보여 준다. 변화가 없으면 안전한 bump다.
3. 출력이 의도대로 바뀌었으면 golden을 갱신해 같은 PR에 커밋한다(`UPDATE_SNAPSHOTS=1`).
4. cdxgen·trivy 메이저 등 영향이 큰 bump는 [배포 절차](release-guide.md)의 도구 업그레이드 체크리스트를 따른다.
5. 계층 4가 이미 이슈로 경고한 깨짐이라면, 그 이슈에 bump PR을 연결해 닫는다.

## Dependabot과의 분담

| 대상 | 담당 |
|---|---|
| npm(electron, web UI), GitHub Actions, base Docker 이미지 | Dependabot(`.github/dependabot.yml`) |
| ARG·셸 변수로 핀된 스캐너 도구, cdxgen 이미지 태그 | Renovate customManager(`renovate.json`) |

두 도구는 대상이 겹치지 않으므로 같은 의존성에 중복 PR을 내지 않는다.
