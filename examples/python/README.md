# Python Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a Python project using pip, a Flask-based REST API with common data-processing and validation libraries.

## Project Structure

- `requirements.txt`: pip dependencies
- `app.py`: a Flask app with a few JSON endpoints

## Dependencies

- **Flask** (3.0.0) and **Werkzeug** (3.0.1): web framework
- **Pandas** (2.1.4) and **NumPy** (1.26.2): data processing
- **Requests** (2.31.0): HTTP client
- **Pydantic** (2.5.2): data validation
- **SQLAlchemy** (2.0.23): database toolkit
- pytest, pytest-cov, black, flake8: testing and lint tools

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat`; see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/python
../../scripts/scan-sbom.sh --project "PythonFlaskExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan writes its outputs into a `PythonFlaskExample_1.0.0/` folder. The main SBOM, `PythonFlaskExample_1.0.0/PythonFlaskExample_1.0.0_bom.json`, lists roughly 30-40 components (including transitive dependencies):
<!-- expected-components: 30-40 -->

- Web framework: flask, werkzeug, jinja2, itsdangerous
- Data processing: pandas, numpy, pytz
- HTTP: requests, urllib3, certifi, charset-normalizer
- Validation: pydantic, pydantic-core
- Database: sqlalchemy, greenlet
- Testing: pytest, pytest-cov, coverage
- Utilities: python-dotenv, click

### Sample Components

- flask
- pandas
- numpy
- requests
- sqlalchemy

## Build and Run (Optional)

```bash
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000
```

## Validate Results

```bash
# Count components
jq '.components | length' PythonFlaskExample_1.0.0/PythonFlaskExample_1.0.0_bom.json

# View the Flask entry
jq -r '.components[] | select(.name | contains("flask")) | "\(.name)@\(.version)"' PythonFlaskExample_1.0.0/PythonFlaskExample_1.0.0_bom.json
```

## Common Issues

### SBOM is empty

```bash
ls -la requirements.txt
pip freeze > requirements.txt
```

**Solution:** confirm `requirements.txt` is present at the project root and lists the installed packages.

### pip install fails

```bash
pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt
```

### Generating an SBOM with cyclonedx-py instead

```bash
pip install cyclonedx-bom
cyclonedx-py requirements -i requirements.txt -o bom.json --format json
```

## Next Steps

- Add more packages to `requirements.txt` and re-scan
- Try a Poetry project (`pyproject.toml` + `poetry.lock`); the same command works, just point `--project` at your own name
- Compare the SBOM before and after adding a new dependency
