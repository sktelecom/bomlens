# 배포 절차 (메인테이너용)

이 문서는 새 버전을 릴리스할 때 따르는 절차를 정리한다. 도구를 사용하려는 분은 이 폴더가 아니라
[docs/](../) 상위의 사용자 가이드를 보세요.

배포는 git 태그 push 한 번으로 자동화돼 있다. `v*.*.*` 형식의 태그를 올리면 세 워크플로가
실행된다. `release.yml`이 GitHub Release와 자산을 만들고, `docker-publish.yml`이 GHCR 이미지를
발행하며, `desktop.yml`이 데스크톱 인스톨러를 붙인다. 코드 변경은 필요하지 않다.

## 릴리스 전 체크리스트

자동 검증이 잡지 못해 사람이 직접 챙겨야 하는 항목이다. 특히 첫 두 가지는 틀려도 CI가 실패하지
않고 결과만 조용히 어긋나므로 반드시 확인한다.

1. **CHANGELOG 헤더를 태그와 글자까지 똑같이 맞춘다(`v` 포함).**
   `release.yml`은 릴리스 노트 본문을 다음과 같이 추출한다.

   ```bash
   sed -n "/## \[vX.Y.Z\]/,/## \[/p" CHANGELOG.md
   ```

   태그가 `v1.2.1`이면 CHANGELOG 헤더도 `## [v1.2.1] - 날짜`여야 매칭된다. `v`를 빼고
   `## [1.2.1]`로 쓰면 CI는 실패하지 않고 릴리스 노트의 Changes 섹션만 빈 채로 발행된다.

2. **`[Unreleased]` 항목을 새 버전 섹션으로 옮겼는지 확인한다.** 릴리스 노트는 버전 섹션에서만
   뽑히므로, 변경 기록이 `[Unreleased]`에 남아 있으면 노트에 반영되지 않는다.

3. **태그는 main에 머지된 커밋에 단다.** `docker-publish.yml`은 main push에도 `:latest`
   이미지를 발행한다. 따라서 PR을 먼저 머지해 main의 latest를 갱신한 뒤, 그 머지 커밋에 태그를
   달아 버전 이미지를 발행하는 순서를 지킨다. main에 없는 커밋에 태그를 달면 `:latest`와 버전
   이미지의 내용이 갈린다.

4. **태그 형식은 3자리 `v*.*.*`다.** 워크플로 트리거가 이 패턴이라서, 2자리(`v1.2`)이거나
   `v`가 없으면 어떤 워크플로도 실행되지 않는다. Docker 이미지의 SemVer 태그(`1.2`, `1`,
   `latest`)도 이 값에서 파생된다.

5. (선택) `electron/package.json`의 version을 새 버전에 맞춘다. 인스톨러 버전은 빌드 시 태그
   값으로 덮어쓰므로 릴리스 차단 요인은 아니지만, 일관성을 위해 맞춘다.

## 릴리스 실행

체크리스트를 마치고 PR이 main에 머지된 뒤 실행한다.

```bash
git checkout main && git pull
git tag vX.Y.Z            # 머지된 main 커밋에서
git push origin vX.Y.Z
```

태그 push로 트리거되는 결과는 세 가지다.

- GitHub Release: 릴리스 노트, 자산 묶음, 무결성 검증용 `SHA256SUMS.txt`. 인스톨러 체크섬은
  release-gate가 인스톨러 첨부를 확인한 뒤 `scripts/attach-installer-checksums.sh`로 덧붙인다.
- GHCR 이미지: `sbom-generator`와 `sbom-scanner` 공동 발행, Android SDK 6종과 firmware
  이미지, cosign 키리스 서명과 SBOM attestation, Trivy 이미지 스캔
- 데스크톱 인스톨러: `BomLens-Setup.exe`와 `BomLens-Setup.dmg`(macOS는 universal —
  Intel과 Apple Silicon 모두 지원). 서명은 CI 시크릿이 등록된 경우에만 켜진다.

주의: 릴리스 공개 후 desktop 워크플로만 재실행해 인스톨러를 교체하면 `SHA256SUMS.txt`의
인스톨러 행이 낡은 값이 된다. 교체 후에는 `scripts/attach-installer-checksums.sh <tag>`를
한 번 다시 실행해 체크섬을 맞춘다.

`workflow_dispatch`로 버전을 직접 입력해 수동 릴리스도 가능하다.

## 릴리스 후 확인

- GitHub Actions에서 release, docker-publish, desktop 세 워크플로가 모두 그린인지 확인한다.
- Release 페이지에서 자산이 첨부됐는지, 노트 본문의 Changes 섹션이 비어 있지 않은지 확인한다.
- 태그 릴리스는 main push보다 무겁고 느리다. Android SDK 이미지 6종(멀티아치)과 firmware
  이미지를 추가로 빌드하기 때문이다. 전체가 그린이 될 때까지 기다려 확인한다.

## 도구 버전 업그레이드

외부 도구(cdxgen·trivy·syft·scanoss·unblob·cve-bin-tool·scancode 등)를 올릴 때 따르는 절차다. 전체 안전장치 설계는 [도구 버전 업그레이드 안전장치](dependency-upgrade-policy.md)를 보세요.

버전 정본은 `docker/Dockerfile`의 ARG와 `docker/lib/source-detect.sh`의 cdxgen 태그다. Renovate가 이들을 추적해 bump PR을 연다. PR이 왔을 때 확인한다.

1. **스냅샷 diff를 본다.** PR의 CI에서 `tests/test-snapshot.sh`가 출력 변화를 diff로 보여 준다. 변화가 없으면 안전한 bump다.
2. **출력이 의도대로 바뀌었으면 golden을 갱신한다.** `UPDATE_SNAPSHOTS=1 bash tests/test-snapshot.sh`로 다시 떠서 같은 PR에 커밋하고, diff가 합당한지 검토한다.
3. **cdxgen 메이저(예: v12에서 v13으로)**는 영향이 크다. 대표 예제 전체 스캔으로 컴포넌트 수와 specVersion이 유지되는지 확인하고, 필드 호환을 점검한다. `upstream-compat.yml`을 `workflow_dispatch`로 미리 돌려 최신 버전 결과를 본다.
4. **trivy 메이저**는 보안 리포트의 검출 범위·심각도 판정을 바꿀 수 있다. 같은 SBOM에 대한 보안 리포트 요약이 어떻게 달라지는지 확인한다.
5. **`upstream-compat`가 연 이슈**가 있으면 해당 bump PR을 연결해 닫는다.

## 재릴리스 주의

같은 버전을 다시 발행하려면 태그, 릴리스, GHCR 이미지 태그를 모두 지우고 덮어야 한다. 실수가
나면 재태그 대신 패치 버전을 올리는 편이 안전하다.
