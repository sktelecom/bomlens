# Ruby Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for Ruby projects using Bundler.

## Project Structure

- `Gemfile`: Bundler dependency definitions
- `app.rb`: Sinatra web server with two JSON endpoints
- Popular Ruby libraries: Sinatra, Puma, Rack

## Dependencies

- **Sinatra** (~3.1): Web framework
- **Puma** (~6.4): Web server
- **Rack** (~2.2): Web server interface
- **JSON** (~2.7): JSON processing
- Plus transitive dependencies

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/start/first-scan.ko.md) 참고.

```bash
cd examples/ruby
../../scripts/scan-sbom.sh --project "RubyExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan writes its outputs into a `RubyExample_1.0.0/` folder. The main SBOM, `RubyExample_1.0.0/RubyExample_1.0.0_bom.json`, contains:
- ~10-15 total components (including transitive dependencies)
- Sinatra and its dependencies (rack, tilt, mustermann, etc.)
- Puma and Rack
- Standard library references

### Sample Components

- sinatra 3.1.x
- puma 6.4.x
- rack 2.2.x
- tilt
- mustermann
- json 2.7.x

## Build and Run (Optional)

```bash
# Install dependencies
bundle install

# Run
ruby app.rb
# Server will start on :4567

# Test
curl http://localhost:4567/
curl http://localhost:4567/health
```

## Validate Results

```bash
# Count components
jq '.components | length' RubyExample_1.0.0/RubyExample_1.0.0_bom.json

# View the Sinatra entry
jq '.components[] | select(.name == "sinatra")' RubyExample_1.0.0/RubyExample_1.0.0_bom.json

# List all gems
jq -r '.components[] | .name' RubyExample_1.0.0/RubyExample_1.0.0_bom.json | sort -u
```

## Common Issues

### Gemfile.lock Missing

The scan resolves dependencies from `Gemfile`, and a `Gemfile.lock` pins the exact
versions.

**Solution:** Run `bundle install` first to generate `Gemfile.lock` for a fully
pinned, reproducible SBOM.

### Gem Resolution Fails

If you see gem resolution errors:

**Solution:** Ensure internet connectivity. The Docker container needs to reach
rubygems.org to resolve dependencies.

## Next Steps

- Add more gems to the `Gemfile`
- Commit `Gemfile.lock` for reproducible, fully pinned SBOMs
- Compare the SBOM before and after `bundle install`
