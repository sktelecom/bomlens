# Ruby Example

SBOM generation example for Ruby projects using Bundler.

## Dependencies

- **Sinatra** (~3.1): Web framework
- **Puma** (~6.4): Web server
- **Rack** (~3.0): Web server interface
- **JSON** (~2.7): JSON processing

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.


```bash
cd examples/ruby
../../scripts/scan-sbom.sh --project "RubyExample" --version "1.0.0" --generate-only
```

## Expected Output

Components: ~10-15 gems including dependencies

```bash
# Validate
jq '.components | length' RubyExample_1.0.0_bom.json
jq '.components[] | select(.name == "sinatra")' RubyExample_1.0.0_bom.json
```

## Run (Optional)

```bash
bundle install
ruby app.rb
# Visit http://localhost:4567
```
