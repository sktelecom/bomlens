# Yocto 지원 검증 절차

Yocto 입력은 세 경로(SPDX 3.0 문서, SPDX 2.2 아카이브, 매니페스트)로 나뉘고, 각 경로가 읽는 파일 형식은 릴리스마다 다릅니다. 이 문서는 **실제 빌드 산출물로 다시 검증하는 방법**과 지금까지 측정한 값을 남깁니다. 파서를 고칠 때 이 수치가 기준선입니다.

## 왜 픽스처만으로는 부족한가

`create-spdx-2.2.bbclass` 소스를 그대로 읽고 만든 픽스처는 실제 배포 형태와 달랐습니다. 소스에는 이미지 문서를 만드는 코드와 그것을 아카이브에 넣는 코드가 모두 있지만, **deploy 디렉터리에 무엇이 남는지**는 산출물을 봐야 알 수 있습니다. 실제로는 `<image>.spdx.tar.zst` 하나만 남고 `<image>.spdx.json`은 남지 않습니다. 이 차이 때문에 초기 구현은 실제 Scarthgap 빌드에서 SBOM을 아예 찾지 못했습니다.

그래서 파서를 바꿀 때는 아래 절차로 실물에 한 번 돌려 봅니다.

## 실물은 어디서 구하나

Yocto 프로젝트가 릴리스마다 참조 이미지 산출물을 공개합니다. 빌드할 필요가 없습니다.

```
https://downloads.yoctoproject.org/releases/yocto/<release>/machines/qemu/qemux86-64/
```

릴리스마다 무엇이 올라오는지가 다르고, 그것이 곧 세 경로의 실물 시료가 됩니다.

| 릴리스 | 공개되는 SBOM | 검증되는 경로 |
|--------|---------------|---------------|
| yocto-4.0.x Kirkstone | 없음(`.manifest`만) | 매니페스트 |
| yocto-5.0.x Scarthgap | `.spdx.tar.zst` | SPDX 2.2 아카이브 |
| yocto-5.2.x 이후 | `.spdx.json` | SPDX 3.0 문서 |

같은 디렉터리의 `<image>.rootfs.manifest`가 정답지입니다. 설치된 패키지를 `<이름> <아키텍처> <버전>` 한 줄씩 담고 있어, 우리 결과와 집합 단위로 대조할 수 있습니다.

## 절차

```bash
B=https://downloads.yoctoproject.org/releases/yocto/yocto-5.0.14/machines/qemu/qemux86-64
curl -fsSLO "$B/core-image-minimal-qemux86-64.rootfs.spdx.tar.zst"
curl -fsSLO "$B/core-image-minimal-qemux86-64.rootfs.manifest"

python3 docker/lib/parse-yocto-spdx.py \
    core-image-minimal-qemux86-64.rootfs.spdx.tar.zst out.cdx.json out

# 컴포넌트 집합이 빌드 자신의 목록과 같은가 (출력이 없으면 일치)
diff <(jq -r '.components[].name' out.cdx.json | sort) \
     <(awk '{print $1}' core-image-minimal-qemux86-64.rootfs.manifest | sort)
```

`zstd`가 필요합니다(이미지에는 들어 있고, 호스트에서 돌릴 때는 직접 설치).

빌드 디렉터리 감지까지 보려면 산출물을 `<build>/tmp/deploy/images/<machine>/` 아래에 두고 `conf/bblayers.conf`를 만든 뒤 `--target <build>`로 스캔합니다.

## 측정값 (기준선)

| 경로 | 시료 | 컴포넌트 | 대조 결과 |
|------|------|----------|-----------|
| SPDX 3.0 | Scarthgap core-image-minimal (ORT 테스트 자산) | 35 | 판정 12255 fixed / 63 not-affected / 0 open |
| SPDX 3.0 | Walnascar 5.2.4 core-image-minimal | 39 | 매니페스트와 완전 일치, 판정 9 / 63 / 0 |
| SPDX 2.2 아카이브 | Scarthgap 5.0.14 core-image-minimal | 36 | 완전 일치, 라이선스 36/36, CPE 35/36 |
| SPDX 2.2 아카이브 | Scarthgap 5.0.14 core-image-full-cmdline | 443 | 완전 일치, 라이선스 443/443, CPE 430/443, 약 0.5초 |
| 매니페스트 | Kirkstone 4.0.28 core-image-minimal | 31 | 완전 일치, cve-check 미실행이라 판정 없음 |

## 알려진 차이 (버그가 아님)

- **커널 패키지 버전.** SPDX 2.2 문서는 `PV`(`6.6.111+git`)를 담고 매니페스트는 `PKGV`(`6.6.111+git0+50530c858c_...`)를 담습니다. Scarthgap `core-image-minimal`에서 36개 중 4개가 여기 해당합니다. 문서 자체의 차이라 우리가 보정하지 않습니다.
- **적합성 필수 실패 2건.** `purl`은 Yocto가 CPE로 식별하기 때문이고(제출 기준을 유지하기로 한 결정), `top-component`는 bitbake가 이미지 패키지에 `software_packageVersion`을 넣지 않기 때문입니다. 둘 다 문서의 사실이므로 값을 지어내지 않습니다.
- **아카이브에는 적합성 보고서를 만들지 않습니다.** 제출된 문서가 아니라 문서 묶음이라 제출 기준과 대조할 대상이 아닙니다.

## 코드 검색으로 구한 실물

릴리스가 공개하지 않는 파일도 공개 저장소에 커밋된 것이 있습니다. GitHub 코드 검색으로 찾았습니다.

- **`license.manifest`** — `"PACKAGE NAME:" "RECIPE NAME:" filename:license.manifest`로 100건 이상. 실제 제품 빌드(PinePhone 모뎀 SDK의 mdm9607 이미지, 57개 패키지)로 파싱을 확인했습니다. 합성 시료에 없던 표현이 여기 있습니다 — 4항·7항 `&` 결합, `PD`처럼 SPDX가 아닌 식별자.
- **`cve-summary.json`** — 파일명으로는 안 나오고, `"scorev3" "Unpatched" "cvesInRecord" extension:json`으로 Jenkins 프로젝트의 테스트 자산에서 실물을 찾았습니다(i.MX 빌드, 12개 레시피). 이 보고서는 12개 중 6개가 `-native` 레시피여서, 빌드 전용 레시피가 이미지 결과에 섞이지 않는지를 실물로 확인하는 데 쓰였습니다.

### 패키지-레시피 매핑이 왜 필수인가 (실측)

cve-check는 **레시피** 기준으로 보고하고, 이미지에 설치되는 것은 **패키지**입니다. 둘의 이름이 다른 경우가 소수가 아닙니다.

| 실물 | 패키지 수 | 이름이 레시피와 다른 패키지 |
|------|-----------|------------------------------|
| Scarthgap 5.0.14 core-image-minimal | 36 | 20 (busybox-syslog→busybox 등) |
| PinePhone 모뎀 SDK mdm9607 | 57 | 32 (kernel-base→linuxmdm 등) |

매핑 없이 이름만 맞춰 보면 절반 이상의 패키지가 자기 CVE를 못 받습니다. `license.manifest`의 `RECIPE NAME`이 그 매핑입니다.

## 아직 실물로 보지 못한 것

- **같은 빌드에서 나온 `license.manifest`와 `cve-summary.json` 한 쌍.** 위 두 실물은 서로 다른 빌드라 레시피가 겹치지 않아, 매핑의 긍정 경로(레시피 CVE가 그 레시피의 패키지들에 붙는 것)는 여전히 합성 시료로만 확인했습니다. 공개된 쌍은 찾지 못했습니다(릴리스의 `testresults/`에도 cve 결과는 없고, per-recipe `*_cve.json`도 공개된 것이 없습니다).
- **진짜 빌드 디렉터리.** 다만 여기서 문제가 되는 것은 파일 내용이 아니라 디렉터리 모양이라, 합성 트리로 재현해 검증했습니다 — `tmp/deploy/spdx/`의 레시피 문서 300개, SDK 문서, `tmp/work`와 `sstate-cache`를 만들어 두고도 이미지 SBOM 하나만 후보로 잡히는지, 감지가 빠른지 확인합니다(`tests/test-e2e.sh`, `tests/test-web-ui.sh`).
- multilib, `TMPDIR`/`DEPLOY_DIR`를 빌드 디렉터리 밖으로 옮긴 설정.

이 항목들은 실제로 빌드를 돌려야 확인됩니다. 빌드 없이 좁힐 수 있는 부분은 위와 같이 좁혀 두었습니다.
