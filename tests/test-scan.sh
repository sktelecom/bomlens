#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ========================================================
# SBOM Generator - Integration Test Script
# ========================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$SCRIPT_DIR/test-workspace"
LOG_DIR="$TEST_DIR/logs"
SCAN_SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
EXAMPLES_DIR="$ROOT_DIR/examples"

# Debug mode (controlled by environment variable)
DEBUG_MODE="${DEBUG_MODE:-false}"
VERBOSE="${VERBOSE:-false}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_debug() { 
    if [ "$DEBUG_MODE" = "true" ] || [ "$VERBOSE" = "true" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

PASSED=0
FAILED=0

cleanup() {
    # Disable exit-on-error for cleanup (we want to clean up as much as possible)
    set +e
    
    echo ""
    echo "=========================================="
    echo " Cleaning up..."
    echo "=========================================="
    
    cd "$ROOT_DIR" 2>/dev/null || true
    
    # Preserve logs if tests failed
    if [ -d "$LOG_DIR" ] && [ $FAILED -gt 0 ]; then
        FAILED_LOGS="$TEST_DIR/failed-tests-logs"
        mkdir -p "$FAILED_LOGS" 2>/dev/null || true
        cp -r "$LOG_DIR"/* "$FAILED_LOGS/" 2>/dev/null || true
        if [ -d "$FAILED_LOGS" ] && [ "$(ls -A "$FAILED_LOGS" 2>/dev/null)" ]; then
            echo ""
            echo "Failed test logs saved to: $FAILED_LOGS"
        fi
    fi
    
    # Clean workspace (except logs) in non-debug mode
    if [ "$DEBUG_MODE" != "true" ] && [ -d "$TEST_DIR" ]; then
        # More robust cleanup
        for item in "$TEST_DIR"/*; do
            if [ -e "$item" ]; then
                basename_item=$(basename "$item")
                if [ "$basename_item" != "logs" ] && [ "$basename_item" != "failed-tests-logs" ]; then
                    rm -rf "$item" 2>/dev/null || true
                fi
            fi
        done
    elif [ "$DEBUG_MODE" = "true" ]; then
        echo "Debug mode: Workspace preserved at $TEST_DIR"
    fi
    
    # Exit with appropriate code based on test results
    # This is critical: return 0 doesn't change script exit code!
    if [ $FAILED -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Find BOM file function. Scans now land in a per-run subfolder
# (<project>_<version>[_<ts>]/), so look there first, then fall back to the
# legacy flat layout for back-compat.
find_bom_file() {
    local project=$1
    local version=$2

    # Per-run subfolder (current layout)
    if [ -f "${project}_${version}/${project}_${version}_bom.json" ]; then
        echo "${project}_${version}/${project}_${version}_bom.json"
        return 0
    fi

    # Single underscore (legacy flat)
    if [ -f "${project}_${version}_bom.json" ]; then
        echo "${project}_${version}_bom.json"
        return 0
    fi

    # Double underscore
    if [ -f "${project}__${version}__bom.json" ]; then
        echo "${project}__${version}__bom.json"
        return 0
    fi

    # Pattern matching: subfolder bundle first, then flat
    local found
    found=$(ls "${project}"*"${version}"*/"${project}"*"${version}"*bom.json 2>/dev/null | head -n1)
    if [ -z "$found" ]; then
        found=$(ls "${project}"*"${version}"*bom.json 2>/dev/null | head -n1)
    fi
    if [ -n "$found" ]; then
        echo "$found"
        return 0
    fi

    return 1
}

# Assert a generated SBOM is well-formed: CycloneDX, the root component carries
# the input project name (not cdxgen's source coords or a temp path), and
# components is an array (not null). Guards the verification-report defects
# B-2/B-3 end-to-end. Returns non-zero on any violation.
assert_bom_sane() {
    local file=$1
    local project=$2
    [ -f "$file" ] || return 1
    jq -e --arg p "$project" \
        '.bomFormat == "CycloneDX"
         and (.metadata.component.name == $p)
         and ((.components | type) == "array")' \
        "$file" >/dev/null 2>&1
}

# Run scan with logging function
run_scan_with_logs() {
    local test_name=$1
    local project=$2
    local version=$3
    shift 3
    local extra_args="$@"
    
    local log_file="$LOG_DIR/${test_name}.log"
    
    print_debug "Running scan for $test_name..."
    print_debug "Log file: $log_file"
    
    if [ "$DEBUG_MODE" = "true" ]; then
        # Debug mode: real-time output + log save
        "$SCAN_SCRIPT" --project "$project" --version "$version" --generate-only $extra_args 2>&1 | tee "$log_file"
        return ${PIPESTATUS[0]}
    elif [ "$VERBOSE" = "true" ]; then
        # Verbose mode: show key messages only
        "$SCAN_SCRIPT" --project "$project" --version "$version" --generate-only $extra_args 2>&1 | tee "$log_file" | grep -E '\[INFO\]|\[WARN\]|\[ERROR\]|Analyzing|Downloading|components|cdxgen|syft' || true
        return ${PIPESTATUS[0]}
    else
        # Normal mode: log only
        "$SCAN_SCRIPT" --project "$project" --version "$version" --generate-only $extra_args > "$log_file" 2>&1
        return $?
    fi
}

# Show failure log function
show_failure_log() {
    local test_name=$1
    local log_file="$LOG_DIR/${test_name}.log"
    
    if [ -f "$log_file" ]; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Failed test log: $test_name"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        # Show last 50 lines or full log
        if [ $(wc -l < "$log_file") -gt 50 ]; then
            echo "... (showing last 50 lines) ..."
            echo ""
            tail -50 "$log_file"
        else
            cat "$log_file"
        fi
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Full log: $log_file"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
    fi
}

echo "=========================================="
echo " SBOM Generator - Integration Test"
echo " Version: 1.0.0"
echo "=========================================="

# Show help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    cat << 'EOF'
Usage: ./test-scan.sh [OPTIONS]

Options:
  --help, -h          Show this help message
  
Environment Variables:
  DEBUG_MODE=true     Enable debug mode (show all output + preserve workspace)
  VERBOSE=true        Enable verbose mode (show key messages only)
  
Examples:
  # Normal mode (quiet, logs saved)
  ./test-scan.sh
  
  # Verbose mode (show key messages)
  VERBOSE=true ./test-scan.sh
  
  # Debug mode (show everything)
  DEBUG_MODE=true ./test-scan.sh
  
  # After test failure, check logs
  cat tests/test-workspace/failed-tests-logs/test-java-maven.log

Logs are saved to: tests/test-workspace/logs/
Failed test logs are preserved in: tests/test-workspace/failed-tests-logs/
EOF
    exit 0
fi

echo ""
if [ "$DEBUG_MODE" = "true" ]; then
    echo "🔍 Debug Mode: Enabled (all logs in real-time)"
elif [ "$VERBOSE" = "true" ]; then
    echo "📋 Verbose Mode: Enabled (key messages shown)"
else
    echo "🔇 Quiet Mode: Enabled (logs saved to files)"
    echo "   Logs shown automatically on failure"
    echo "   Verbose: VERBOSE=true ./test-scan.sh"
    echo "   Debug: DEBUG_MODE=true ./test-scan.sh"
fi
echo ""

# ========================================================
# Prerequisites Check
# ========================================================
print_header "Checking prerequisites..."

# Docker check
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    print_error "Docker daemon is not running"
    exit 1
fi
print_success "Docker check passed"

# Script check
if [ ! -f "$SCAN_SCRIPT" ]; then
    print_error "scan-sbom.sh not found: $SCAN_SCRIPT"
    exit 1
fi
chmod +x "$SCAN_SCRIPT"
print_success "Scan script check passed"

# Create test directory
mkdir -p "$TEST_DIR"
mkdir -p "$LOG_DIR"
cd "$TEST_DIR" || true

trap cleanup EXIT

echo ""
print_header "Starting tests..."
echo ""

# ========================================================
# Test 1: Node.js project
# ========================================================
print_test "Test 1/15: Node.js project (npm)"

mkdir -p node-project
cd node-project || true

cat > package.json <<'EOF'
{
  "name": "test-nodejs-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}
EOF

npm install --package-lock-only > /dev/null 2>&1 || true

if run_scan_with_logs "test-nodejs" "TestNodeApp" "1.0.0"; then
    if FOUND=$(find_bom_file "TestNodeApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Node.js project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Node.js project (SBOM is empty)"
            show_failure_log "test-nodejs"
            ((FAILED++))
        fi
    else
        print_error "Node.js project (SBOM file not generated)"
        show_failure_log "test-nodejs"
        ((FAILED++))
    fi
else
    print_error "Node.js project (Scan failed)"
    show_failure_log "test-nodejs"
    ((FAILED++))
fi


cd "$TEST_DIR" || true

# ========================================================
# Test 2: Python project
# ========================================================
print_test "Test 2/15: Python project (pip)"

mkdir -p python-project
cd python-project || true

cat > requirements.txt <<'EOF'
flask==3.0.0
requests==2.31.0
pandas==2.1.0
EOF

if run_scan_with_logs "test-python" "TestPythonApp" "1.0.0"; then
    if FOUND=$(find_bom_file "TestPythonApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Python project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Python project (SBOM is empty)"
            show_failure_log "test-python"
            ((FAILED++))
        fi
    else
        print_error "Python project (SBOM file not generated)"
        show_failure_log "test-python"
        ((FAILED++))
    fi
else
    print_error "Python project (Scan failed)"
    show_failure_log "test-python"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 3: Java Maven project
# ========================================================
print_test "Test 3/15: Java Maven project"

mkdir -p java-maven-project
cd java-maven-project || true

cat > pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.0</version>
        </dependency>
    </dependencies>
</project>
EOF

if run_scan_with_logs "test-java-maven" "TestJavaMaven" "1.0.0"; then
    if FOUND=$(find_bom_file "TestJavaMaven" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Java Maven project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Java Maven project (SBOM is empty)"
            show_failure_log "test-java-maven"
            ((FAILED++))
        fi
    else
        print_error "Java Maven project (SBOM file not generated)"
        show_failure_log "test-java-maven"
        ((FAILED++))
    fi
else
    print_error "Java Maven project (Scan failed)"
    show_failure_log "test-java-maven"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 4: Ruby project
# ========================================================
print_test "Test 4/15: Ruby project (Bundler)"

mkdir -p ruby-project
cd ruby-project || true

cat > Gemfile <<'EOF'
source 'https://rubygems.org'

gem 'sinatra', '~> 3.0'
gem 'rack', '~> 2.2'
EOF

if run_scan_with_logs "test-ruby" "TestRubyApp" "1.0.0"; then
    if FOUND=$(find_bom_file "TestRubyApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Ruby project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Ruby project (SBOM is empty)"
            show_failure_log "test-ruby"
            ((FAILED++))
        fi
    else
        print_error "Ruby project (SBOM file not generated)"
        show_failure_log "test-ruby"
        ((FAILED++))
    fi
else
    print_error "Ruby project (Scan failed)"
    show_failure_log "test-ruby"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 5: PHP project
# ========================================================
print_test "Test 5/15: PHP project (Composer)"

mkdir -p php-project
cd php-project || true

cat > composer.json <<'EOF'
{
    "name": "test/php-app",
    "require": {
        "monolog/monolog": "^3.0",
        "guzzlehttp/guzzle": "^7.5"
    }
}
EOF

if run_scan_with_logs "test-php" "TestPHPApp" "1.0.0"; then
    if FOUND=$(find_bom_file "TestPHPApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "PHP project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "PHP project (SBOM is empty)"
            show_failure_log "test-php"
            ((FAILED++))
        fi
    else
        print_error "PHP project (SBOM file not generated)"
        show_failure_log "test-php"
        ((FAILED++))
    fi
else
    print_error "PHP project (Scan failed)"
    show_failure_log "test-php"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 6: Rust project
# ========================================================
print_test "Test 6/15: Rust project (Cargo)"

mkdir -p rust-project
cd rust-project || true

cat > Cargo.toml <<'EOF'
[package]
name = "test-rust-app"
version = "1.0.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
EOF

if run_scan_with_logs "test-rust" "TestRustApp" "1.0.0"; then
    if FOUND=$(find_bom_file "TestRustApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Rust project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Rust project (SBOM is empty)"
            show_failure_log "test-rust"
            ((FAILED++))
        fi
    else
        print_error "Rust project (SBOM file not generated)"
        show_failure_log "test-rust"
        ((FAILED++))
    fi
else
    print_error "Rust project (Scan failed)"
    show_failure_log "test-rust"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 7: Docker image analysis
# ========================================================
print_test "Test 7/15: Docker image analysis"

# Pull alpine image if network available
if docker pull alpine:latest > /dev/null 2>&1; then
    if run_scan_with_logs "test-docker-image" "TestDockerImage" "1.0.0" "--target alpine:latest"; then
        if FOUND=$(find_bom_file "TestDockerImage" "1.0.0"); then
            COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
            if [ "$COMP_COUNT" -gt 0 ]; then
                print_success "Docker Image ($COMP_COUNT components)"
                ((PASSED++))
            else
                print_error "Docker Image (SBOM is empty)"
                show_failure_log "test-docker-image"
                ((FAILED++))
            fi
        else
            print_error "Docker Image (SBOM file not generated)"
            show_failure_log "test-docker-image"
            ((FAILED++))
        fi
    else
        print_error "Docker Image (Scan failed)"
        show_failure_log "test-docker-image"
        ((FAILED++))
    fi
else
    print_error "Docker Image (Cannot pull alpine:latest - network issue)"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 8: Binary file analysis
# ========================================================
print_test "Test 8/15: Binary file analysis"

mkdir -p binary-test
cd binary-test || true

# Create a simple binary file
echo "#!/bin/sh" > test-binary
echo "echo 'test'" >> test-binary
chmod +x test-binary

if run_scan_with_logs "test-binary" "TestBinary" "1.0.0" "--target test-binary"; then
    if FOUND=$(find_bom_file "TestBinary" "1.0.0"); then
        print_success "Binary File"
        ((PASSED++))
    else
        print_error "Binary File (SBOM file not generated)"
        show_failure_log "test-binary"
        ((FAILED++))
    fi
else
    print_error "Binary File (Scan failed)"
    show_failure_log "test-binary"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 9: RootFS directory analysis
# ========================================================
print_test "Test 9/15: RootFS directory analysis"

mkdir -p rootfs-test/usr/bin
cd rootfs-test || true

# Create minimal rootfs structure
echo "test" > usr/bin/test-file

if run_scan_with_logs "test-rootfs" "TestRootFS" "1.0.0" "--target ."; then
    if FOUND=$(find_bom_file "TestRootFS" "1.0.0"); then
        print_success "RootFS Directory"
        ((PASSED++))
    else
        print_error "RootFS Directory (SBOM file not generated)"
        show_failure_log "test-rootfs"
        ((FAILED++))
    fi
else
    print_error "RootFS Directory (Scan failed)"
    show_failure_log "test-rootfs"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 10: Example projects validation
# ========================================================
print_test "Test 10/15: Example project validation"

EXAMPLE_PASSED=0
EXAMPLE_TOTAL=0

for example in "$EXAMPLES_DIR"/*; do
    if [ -d "$example" ]; then
        example_name=$(basename "$example")
        ((EXAMPLE_TOTAL++))
        
        cd "$example"
        
        # Check if README exists
        if [ -f "README.md" ]; then
            ((EXAMPLE_PASSED++))
        fi
        
        cd "$TEST_DIR"
    fi
done

if [ $EXAMPLE_TOTAL -eq $EXAMPLE_PASSED ]; then
    print_success "Example Project ($EXAMPLE_PASSED/$EXAMPLE_TOTAL complete)"
    ((PASSED++))
else
    print_error "Example Project ($EXAMPLE_PASSED/$EXAMPLE_TOTAL complete)"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 11: ZIP archive ingestion (auto-extract -> source scan)
# Exercises native archive ingestion + risk-report (default-on, all modes).
# ========================================================
print_test "Test 11/15: ZIP archive ingestion"

if ! command -v zip > /dev/null 2>&1; then
    print_error "ZIP ingestion (zip command unavailable)"
    ((FAILED++))
else
    mkdir -p zip-src/app
    cat > zip-src/app/package.json <<'EOF'
{ "name": "zip-app", "version": "1.0.0", "dependencies": { "express": "^4.18.0" } }
EOF
    ( cd zip-src && zip -qr app.zip app )
    cd zip-src || true
    if run_scan_with_logs "test-zip" "TestZipApp" "1.0.0" "--target app.zip --all"; then
        if find_bom_file "TestZipApp" "1.0.0" > /dev/null \
           && [ -f "TestZipApp_1.0.0_risk-report.md" ]; then
            print_success "ZIP ingestion (SBOM + risk-report)"
            ((PASSED++))
        else
            print_error "ZIP ingestion (SBOM or risk-report missing)"
            show_failure_log "test-zip"
            ((FAILED++))
        fi
    else
        print_error "ZIP ingestion (Scan failed)"
        show_failure_log "test-zip"
        ((FAILED++))
    fi
    cd "$TEST_DIR" || true
fi

# ========================================================
# Test 12: Python --byte-stable reproducibility + metadata/array sanity
# Two scans of the same input must be byte-identical (B-1; python is the
# language that builds a temp venv whose random name used to leak), and the
# stamped SBOM must carry the input project name with an array components (B-2/B-3).
# ========================================================
print_test "Test 12/15: Python --byte-stable reproducibility"

mkdir -p bytestable-project
cd bytestable-project || true
cat > requirements.txt <<'EOF'
flask==3.0.0
click==8.1.7
EOF

bs_ok=true
if run_scan_with_logs "test-bytestable-1" "ByteStable" "1.0.0" "--byte-stable"; then
    if F1=$(find_bom_file "ByteStable" "1.0.0"); then cp "$F1" "$TEST_DIR/bs1.json"; else bs_ok=false; fi
else
    bs_ok=false
fi
rm -rf ./ByteStable_1.0.0*/ ./*_bom.json
if run_scan_with_logs "test-bytestable-2" "ByteStable" "1.0.0" "--byte-stable"; then
    if F2=$(find_bom_file "ByteStable" "1.0.0"); then cp "$F2" "$TEST_DIR/bs2.json"; else bs_ok=false; fi
else
    bs_ok=false
fi

if [ "$bs_ok" = true ] \
   && diff -q "$TEST_DIR/bs1.json" "$TEST_DIR/bs2.json" >/dev/null 2>&1 \
   && assert_bom_sane "$TEST_DIR/bs2.json" "ByteStable"; then
    print_success "Python --byte-stable (two scans byte-identical, metadata sane)"
    ((PASSED++))
else
    print_error "Python --byte-stable (non-reproducible or metadata/components invalid)"
    show_failure_log "test-bytestable-2"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 13: Source scan isolates its bundle and keeps the scanned tree clean
# (regression for outputs being dumped flat into the user's source dir).
# ========================================================
print_test "Test 13/15: Source scan output isolation"

mkdir -p isolation-project
cd isolation-project || true
cat > requirements.txt <<'EOF'
flask==3.0.0
EOF

iso_ok=true
if run_scan_with_logs "test-isolation" "Isolation" "1.0.0"; then
    # Bundle must land in the per-run subfolder...
    [ -f "Isolation_1.0.0/Isolation_1.0.0_bom.json" ] || iso_ok=false
    # ...and nothing must leak flat into the scanned tree.
    stray=$(ls ./*_bom.json 2>/dev/null | head -n1)
    [ -z "$stray" ] || iso_ok=false
else
    iso_ok=false
fi

if [ "$iso_ok" = true ]; then
    print_success "Source scan keeps the tree clean (bundle in Isolation_1.0.0/)"
    ((PASSED++))
else
    print_error "Source scan leaked artifacts into the scanned tree"
    show_failure_log "test-isolation"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 14: --output-dir places the bundle under the given base directory.
# ========================================================
print_test "Test 14/15: --output-dir base directory"

mkdir -p outdir-project
cd outdir-project || true
cat > requirements.txt <<'EOF'
click==8.1.7
EOF

CUSTOM_OUT="$TEST_DIR/custom-output"
od_ok=true
if run_scan_with_logs "test-outdir" "OutDir" "1.0.0" "--output-dir $CUSTOM_OUT"; then
    [ -f "$CUSTOM_OUT/OutDir_1.0.0/OutDir_1.0.0_bom.json" ] || od_ok=false
else
    od_ok=false
fi

if [ "$od_ok" = true ]; then
    print_success "--output-dir honored ($CUSTOM_OUT/OutDir_1.0.0/)"
    ((PASSED++))
else
    print_error "--output-dir not honored"
    show_failure_log "test-outdir"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Test 15: --timestamp keeps repeat scans side by side in dated folders.
# ========================================================
print_test "Test 15/15: --timestamp run folder"

mkdir -p stamp-project
cd stamp-project || true
cat > requirements.txt <<'EOF'
click==8.1.7
EOF

ts_ok=true
if run_scan_with_logs "test-timestamp" "Stamped" "1.0.0" "--timestamp"; then
    tsdir=$(ls -d ./Stamped_1.0.0_*/ 2>/dev/null | head -n1)
    if [ -n "$tsdir" ] && [ -f "${tsdir}Stamped_1.0.0_bom.json" ]; then :; else ts_ok=false; fi
else
    ts_ok=false
fi

if [ "$ts_ok" = true ]; then
    print_success "--timestamp run folder created ($tsdir)"
    ((PASSED++))
else
    print_error "--timestamp did not create a timestamped folder"
    show_failure_log "test-timestamp"
    ((FAILED++))
fi

cd "$TEST_DIR" || true

# ========================================================
# Summary
# ========================================================
echo ""
echo "=========================================="
echo " Test Summary"
echo "=========================================="
echo ""
echo "Total tests: $((PASSED + FAILED))"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    SUCCESS_RATE="100.0"
else
    SUCCESS_RATE=$(awk "BEGIN {printf \"%.1f\", ($PASSED/($PASSED+$FAILED))*100}")
fi

echo "Success rate: ${SUCCESS_RATE}%"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "Failed test logs available at:"
    echo "  $TEST_DIR/failed-tests-logs/"
    echo ""
    exit 1
fi

exit 0