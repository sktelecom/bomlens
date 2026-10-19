---
description: 릴리스 파일과 컨테이너 이미지가 이 프로젝트가 빌드한 것이 맞는지 cosign으로 확인하고, 이미지와 함께 배포되는 SBOM을 읽는 방법을 설명합니다.
---

# 릴리스 검증

공급망을 다루는 도구라면 그 도구의 공급망도 확인할 수 있어야 합니다. 모든 릴리스는 프로젝트의 GitHub Actions 워크플로가 빌드하고 키 없는(keyless) [cosign](https://docs.sigstore.dev/cosign/overview/)(Sigstore)으로 서명합니다. 그래서 누군가 건네준 키를 믿지 않고도, 내려받은 파일이 이 저장소에서 빌드된 것인지 확인할 수 있습니다.

아래 명령은 v1.13.7으로 실행해 확인했습니다. 내려받은 버전으로 바꿔 쓰세요. `cosign` v2가 필요하고, 체크섬 확인에는 `sha256sum`(macOS는 `shasum -a 256`)이 필요합니다.

## 릴리스 파일(설치 파일, CLI, 소스 묶음)

서명 하나가 체크섬 파일을 덮고 체크섬 파일이 모든 산출물을 덮으므로, 체크섬 파일을 검증한 뒤 체크섬을 대조합니다.

```bash
VERSION=v1.13.7
gh release download "$VERSION" --repo sktelecom/bomlens \
  --pattern 'SHA256SUMS.txt*' --pattern 'BomLens-Setup.exe'

cosign verify-blob SHA256SUMS.txt \
  --signature SHA256SUMS.txt.sig \
  --certificate SHA256SUMS.txt.pem \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK

sha256sum -c SHA256SUMS.txt --ignore-missing
# BomLens-Setup.exe: OK
```

`Verified OK`는 체크섬 파일이 `sktelecom/bomlens` 저장소의 워크플로로 서명됐다는 뜻입니다. 이어서 나오는 `OK` 줄은 내려받은 파일이 그 체크섬과 일치한다는 뜻입니다. 데스크톱 설치 파일은 아직 코드 서명이 없어서 처음 실행할 때 SmartScreen이나 Gatekeeper 경고가 나옵니다([첫 스캔](../start/first-scan.ko.md) 참고). 이 검증이 그 파일이 프로젝트의 빌드가 맞는지 확인하는 방법입니다.

### Windows에서

이 확인에는 `gh`, `sha256sum`, `jq`가 필요 없습니다. [cosign 릴리스 페이지](https://github.com/sigstore/cosign/releases/latest)에서 `cosign-windows-amd64`를 작업할 폴더에 내려받아 이름을 `cosign.exe`로 바꾼 뒤 PowerShell에서 아래를 실행하세요. 설치 파일과 체크섬 파일을 내려받고, 체크섬 파일의 서명을 확인한 다음, 설치 파일의 해시가 목록의 값과 같은지 비교합니다.

```powershell
$v = "v1.13.7"
$base = "https://github.com/sktelecom/bomlens/releases/download/$v"
foreach ($f in "SHA256SUMS.txt","SHA256SUMS.txt.sig","SHA256SUMS.txt.pem","BomLens-Setup.exe") {
  Invoke-WebRequest "$base/$f" -OutFile $f
}

.\cosign.exe verify-blob SHA256SUMS.txt `
  --signature SHA256SUMS.txt.sig `
  --certificate SHA256SUMS.txt.pem `
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK

$want = ((Select-String -Path SHA256SUMS.txt -Pattern 'BomLens-Setup.exe').Line -split '\s+')[0]
$got = (Get-FileHash BomLens-Setup.exe -Algorithm SHA256).Hash
if ($want -ieq $got) { "OK: BomLens-Setup.exe matches" } else { "MISMATCH" }
```

마지막 줄에 `MISMATCH`가 나오면 설치 파일을 실행하지 마세요.

## 컨테이너 이미지

이미지는 digest 단위로 서명하며, 이미지마다 자기 SBOM을 서명된 증명(attestation)으로 함께 답니다.

```bash
cosign verify ghcr.io/sktelecom/bomlens:1.13.7 \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

증명에서 이미지의 SBOM(CycloneDX)을 꺼내 읽으려면 다음과 같이 합니다.

```bash
cosign verify-attestation --type cyclonedx ghcr.io/sktelecom/bomlens:1.13.7 \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | head -1 | jq -r '.payload | @base64d | fromjson | .predicate' > bomlens-image.cdx.json
```

이렇게 꺼낸 SBOM은 BomLens로 다시 검토할 수 있습니다. `scan-sbom.sh --analyze bomlens-image.cdx.json --project bomlens-image --version 1.13.7`

## 프로젝트 자체의 SBOM

릴리스마다 `bomlens-source-<version>.cdx.json`도 붙습니다. 저장소가 배포하는 모든 매니페스트(데스크톱 앱과 웹 UI의 의존성)의 SBOM이며, 같은 체크섬 파일이 덮습니다.

## 이 검증이 알려 주지 않는 것

유효한 서명은 누가 빌드했는지를 알려 줄 뿐, 코드에 결함이 없다는 뜻이 아닙니다. 스캐너 이미지는 매일 밤 Trivy로 검사하고 그 결과는 저장소의 Security 탭에 공개됩니다. 도구가 하지 않는 일은 [한계](../concepts/limitations.ko.md) 문서에 정리했습니다.
