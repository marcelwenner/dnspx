#!/bin/bash

set -e

get_cargo_info() {
    if [[ ! -f "Cargo.toml" ]]; then
        log_error "Cargo.toml not found in current directory"
        exit 1
    fi
    
    if command -v jq &> /dev/null; then
        log_info "Using cargo metadata for parsing (more robust)"
        
        PROJECT_NAME=$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[0].name')
        VERSION=$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[0].version')
        
        if [[ "$PROJECT_NAME" == "null" ]] || [[ "$VERSION" == "null" ]] || [[ -z "$PROJECT_NAME" ]] || [[ -z "$VERSION" ]]; then
            log_warning "cargo metadata failed, falling back to grep/sed parsing"
            parse_cargo_toml_manually
        fi
    else
        log_info "jq not found, using grep/sed parsing"
        parse_cargo_toml_manually
    fi
    
    if [[ -z "$PROJECT_NAME" ]] || [[ -z "$VERSION" ]]; then
        log_error "Could not extract project name or version from Cargo.toml"
        exit 1
    fi
    
    log_success "Project: $PROJECT_NAME"
    log_success "Version: $VERSION"
}

parse_cargo_toml_manually() {
    PROJECT_NAME=$(grep '^name = ' Cargo.toml | head -1 | sed 's/name = "\(.*\)"/\1/')
    VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
}

RELEASE_DIR="release"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust."
        exit 1
    fi
    
    if ! command -v git &> /dev/null; then
        log_error "Git not found. Please install Git."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

install_targets() {
    log_info "Installing cross-compilation targets..."
    
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-apple-darwin
    rustup target add aarch64-apple-darwin
    rustup target add x86_64-pc-windows-gnu
    
    if [[ "$OSTYPE" == "darwin"* ]] && ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        log_info "Installing mingw-w64 for Windows cross-compilation..."
        if command -v brew &> /dev/null; then
            brew install mingw-w64
        else
            log_warning "Homebrew not found. Please install mingw-w64 manually for Windows builds"
        fi
    fi
    
    log_success "Cross-compilation targets installed"
}

clean_builds() {
    log_info "Cleaning previous builds..."
    cargo clean
    rm -rf "$RELEASE_DIR"
    mkdir -p "$RELEASE_DIR"
    log_success "Clean completed"
}

build_target() {
    local target=$1
    local output_name=$2
    
    log_info "Building for target: $target"
    
    if [[ "$target" == *"windows"* ]]; then
        cargo build --release --target "$target"
        cp "target/$target/release/${PROJECT_NAME}.exe" "$RELEASE_DIR/${output_name}.exe"
    else
        cargo build --release --target "$target"
        cp "target/$target/release/$PROJECT_NAME" "$RELEASE_DIR/$output_name"
    fi
    
    log_success "Built $output_name"
}

generate_checksums() {
    log_info "Generating checksums..."
    
    cd "$RELEASE_DIR"
    
    if command -v sha256sum &> /dev/null; then
        sha256sum ./* > checksums.txt
    elif command -v shasum &> /dev/null; then
        shasum -a 256 ./* > checksums.txt
    else
        log_warning "No SHA256 utility found. Checksums not generated."
        cd ..
        return
    fi
    
    log_success "Checksums generated in checksums.txt"
    cd ..
}

create_archives() {
    log_info "Creating release archives..."
    
    cd "$RELEASE_DIR"
    
    for file in dnspx-*; do
        if [[ -f "$file" ]]; then
            if [[ "$file" == *.exe ]]; then
                zip "${file%.exe}.zip" "$file" ../README.md ../LICENSE ../CHANGELOG.md
            else
                tar -czf "${file}.tar.gz" "$file" ../README.md ../LICENSE ../CHANGELOG.md
            fi
            log_success "Created archive for $file"
        fi
    done
    
    cd ..
}

main() {
    echo "========================================"
    echo "Cross-Platform Release Builder"
    echo "========================================"
    
    check_prerequisites
    get_cargo_info
    
    echo "Building $PROJECT_NAME v$VERSION"
    echo "========================================"
    
    install_targets
    clean_builds
    
    log_info "Starting cross-platform builds on macOS..."
    
    build_target "x86_64-unknown-linux-gnu" "${PROJECT_NAME}-v${VERSION}-linux-x64"
    
    build_target "x86_64-apple-darwin" "${PROJECT_NAME}-v${VERSION}-macos-intel"
    
    build_target "aarch64-apple-darwin" "${PROJECT_NAME}-v${VERSION}-macos-arm64"
    
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        build_target "x86_64-pc-windows-gnu" "${PROJECT_NAME}-v${VERSION}-windows-x64"
    else
        log_warning "mingw-w64 not found, skipping Windows build"
        log_info "Install with: brew install mingw-w64"
    fi
    
    generate_checksums
    create_archives
    
    echo ""
    echo "========================================"
    log_success "Release build completed!"
    echo "========================================"
    echo ""
    echo "Built files in $RELEASE_DIR/:"
    ls -la "$RELEASE_DIR/"
}

main "$@"
