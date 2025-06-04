#!/bin/bash
# build-release.sh - Cross-platform release builder for DNSPX

set -e  # Exit on any error

# Parse project info from Cargo.toml
get_cargo_info() {
    if [[ ! -f "Cargo.toml" ]]; then
        log_error "Cargo.toml not found in current directory"
        exit 1
    fi
    
    # Use cargo metadata for robust parsing if jq is available
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
    # Extract project name and version using grep and sed
    PROJECT_NAME=$(grep '^name = ' Cargo.toml | head -1 | sed 's/name = "\(.*\)"/\1/')
    VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
}

# Configuration
RELEASE_DIR="release"

# Colors
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

# Check prerequisites
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
    
    # Check CMake for Windows cross-compilation
    if ! command -v cmake &> /dev/null; then
        log_warning "CMake not found - required for Windows cross-compilation"
        if command -v brew &> /dev/null; then
            log_info "Installing CMake via Homebrew..."
            brew install cmake
            log_success "CMake installed"
        else
            log_error "Please install CMake manually for Windows builds"
            log_error "  macOS: brew install cmake"
            log_error "  Or download from: https://cmake.org/download/"
        fi
    fi
    
    log_success "Prerequisites check passed"
}

# Install cross-compilation targets
install_targets() {
    log_info "Installing cross-compilation targets..."
    
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-apple-darwin
    rustup target add aarch64-apple-darwin
    rustup target add x86_64-pc-windows-gnu
    
    # Install mingw for Windows cross-compilation on macOS
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

# Clean previous builds
clean_builds() {
    log_info "Cleaning previous builds..."
    cargo clean
    rm -rf "$RELEASE_DIR"
    mkdir -p "$RELEASE_DIR"
    log_success "Clean completed"
}

# Build function for a specific target
build_target() {
    local target=$1
    local output_name=$2
    
    log_info "Building optimized binary for target: $target"
    
    if [[ "$target" == *"windows"* ]]; then
        # Windows needs .exe extension
        cargo build --release --target "$target"
        cp "target/$target/release/${PROJECT_NAME}.exe" "$RELEASE_DIR/${output_name}.exe"
        
        # Check size and warn if large
        size=$(stat -f%z "$RELEASE_DIR/${output_name}.exe" 2>/dev/null || stat -c%s "$RELEASE_DIR/${output_name}.exe" 2>/dev/null)
        size_mb=$((size / 1024 / 1024))
        log_success "Built $output_name.exe (${size_mb}MB)"
    else
        cargo build --release --target "$target"
        cp "target/$target/release/$PROJECT_NAME" "$RELEASE_DIR/$output_name"
        
        # Check size and warn if large
        size=$(stat -f%z "$RELEASE_DIR/$output_name" 2>/dev/null || stat -c%s "$RELEASE_DIR/$output_name" 2>/dev/null)
        size_mb=$((size / 1024 / 1024))
        log_success "Built $output_name (${size_mb}MB)"
        
        if [[ $size_mb -gt 20 ]]; then
            log_warning "Binary is ${size_mb}MB - consider size optimizations"
        fi
    fi
}

# Generate checksums
generate_checksums() {
    log_info "Generating checksums..."
    
    cd "$RELEASE_DIR"
    
    # Generate SHA256 checksums (safe glob expansion)
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

# Create GitHub release archive
create_archives() {
    log_info "Creating release archives..."
    
    cd "$RELEASE_DIR"
    
    # Create individual archives for each binary
    for file in dnspx-*; do
        if [[ -f "$file" ]]; then
            if [[ "$file" == *.exe ]]; then
                # Windows
                zip "${file%.exe}.zip" "$file" ../README.md ../LICENSE ../CHANGELOG.md
            else
                # Unix systems
                tar -czf "${file}.tar.gz" "$file" ../README.md ../LICENSE ../CHANGELOG.md
            fi
            log_success "Created archive for $file"
        fi
    done
    
    cd ..
}

# Main build process
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
    
    # Build for different platforms (Windows + macOS priority)
    log_info "Starting builds - prioritizing Windows and macOS..."
    
    # macOS builds (always work)
    build_target "x86_64-apple-darwin" "${PROJECT_NAME}-v${VERSION}-macos-intel"
    build_target "aarch64-apple-darwin" "${PROJECT_NAME}-v${VERSION}-macos-arm64"
    
    # Windows builds (multiple approaches)
    log_info "Attempting Windows cross-compilation..."
    
    # Try MSVC first (often works out of box)
    if rustup target list --installed | grep -q "x86_64-pc-windows-msvc"; then
        log_info "Trying Windows MSVC target..."
        if cargo build --release --target x86_64-pc-windows-msvc 2>/dev/null; then
            cp "target/x86_64-pc-windows-msvc/release/${PROJECT_NAME}.exe" "$RELEASE_DIR/${PROJECT_NAME}-v${VERSION}-windows-x64.exe"
            log_success "Built ${PROJECT_NAME}-v${VERSION}-windows-x64.exe (MSVC)"
        else
            log_warning "MSVC build failed, trying MinGW..."
            try_mingw_build
        fi
    else
        log_info "Installing MSVC target..."
        rustup target add x86_64-pc-windows-msvc
        if cargo build --release --target x86_64-pc-windows-msvc 2>/dev/null; then
            cp "target/x86_64-pc-windows-msvc/release/${PROJECT_NAME}.exe" "$RELEASE_DIR/${PROJECT_NAME}-v${VERSION}-windows-x64.exe"
            log_success "Built ${PROJECT_NAME}-v${VERSION}-windows-x64.exe (MSVC)"
        else
            try_mingw_build
        fi
    fi
    
    # Linux x64 (best effort)
    if command -v x86_64-linux-musl-gcc &> /dev/null; then
        log_info "Building Linux binary with musl..."
        rustup target add x86_64-unknown-linux-musl
        build_target "x86_64-unknown-linux-musl" "${PROJECT_NAME}-v${VERSION}-linux-x64"
    else
        log_info "Linux cross-compilation not available (install musl-cross for Linux builds)"
    fi
}

try_mingw_build() {
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        log_info "Trying MinGW build..."
        export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
        export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
        build_target "x86_64-pc-windows-gnu" "${PROJECT_NAME}-v${VERSION}-windows-x64"
    elif command -v zig &> /dev/null && command -v cargo-zigbuild &> /dev/null; then
        log_info "Trying Zig cross-compilation..."
        cargo zigbuild --release --target x86_64-pc-windows-gnu
        cp "target/x86_64-pc-windows-gnu/release/${PROJECT_NAME}.exe" "$RELEASE_DIR/${PROJECT_NAME}-v${VERSION}-windows-x64.exe"
        log_success "Built ${PROJECT_NAME}-v${VERSION}-windows-x64.exe (Zig)"
    else
        log_error "Windows cross-compilation failed!"
        log_info "Install options:"
        log_info "  - MinGW: brew install mingw-w64"
        log_info "  - Zig: brew install zig && cargo install cargo-zigbuild"
        return 1
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
    echo ""
    
    # Summary of total sizes
    log_info "Binary size summary:"
    total_size=0
    for file in "$RELEASE_DIR"/*; do
        if [[ -f "$file" ]] && [[ "$file" != *"checksums.txt" ]] && [[ "$file" != *".tar.gz" ]] && [[ "$file" != *".zip" ]]; then
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
            size_mb=$((size / 1024 / 1024))
            filename=$(basename "$file")
            echo "  $filename: ${size_mb}MB"
            total_size=$((total_size + size))
        fi
    done
    
    if [[ $total_size -gt 0 ]]; then
        total_mb=$((total_size / 1024 / 1024))
        echo "  Total: ${total_mb}MB"
    fi
}

# Run main function
main "$@"