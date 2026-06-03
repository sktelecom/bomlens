# PHP Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/getting-started.en.md) and the [usage guide](../../docs/usage-guide.en.md).
Composer-based PHP project example.
## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.

```bash
../../scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --generate-only
```
