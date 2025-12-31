#!/bin/bash
# HysterGuard 构建脚本

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/output"
VERSION="${VERSION:-0.1.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S')"

LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

# 支持的平台
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
    "windows/386"
)

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 构建函数
build_binary() {
    local os=$1
    local arch=$2
    local component=$3
    
    local output_name="${component}-${os}-${arch}"
    if [ "$os" == "windows" ]; then
        output_name="${output_name}.exe"
    fi
    
    local output_path="${BUILD_DIR}/${output_name}"
    
    log_info "Building ${component} for ${os}/${arch}..."
    
    GOOS=$os GOARCH=$arch go build \
        -ldflags "${LDFLAGS}" \
        -o "${output_path}" \
        "./cmd/${component}"
    
    if [ -f "${output_path}" ]; then
        log_info "Built: ${output_path}"
        return 0
    else
        log_error "Failed to build: ${output_path}"
        return 1
    fi
}

# 构建所有平台
build_all() {
    mkdir -p "${BUILD_DIR}"
    
    log_info "Building HysterGuard v${VERSION} (${COMMIT})"
    log_info "Build directory: ${BUILD_DIR}"
    
    for platform in "${PLATFORMS[@]}"; do
        IFS='/' read -r os arch <<< "$platform"
        
        build_binary "$os" "$arch" "client" || true
        build_binary "$os" "$arch" "server" || true
    done
    
    log_info "Build complete!"
    ls -la "${BUILD_DIR}"
}

# 仅构建当前平台
build_current() {
    mkdir -p "${BUILD_DIR}"
    
    local os=$(go env GOOS)
    local arch=$(go env GOARCH)
    
    log_info "Building for current platform: ${os}/${arch}"
    
    build_binary "$os" "$arch" "client"
    build_binary "$os" "$arch" "server"
}

# 仅构建 Linux
build_linux() {
    mkdir -p "${BUILD_DIR}"
    
    log_info "Building for Linux platforms..."
    
    for platform in "${PLATFORMS[@]}"; do
        if [[ "$platform" == linux/* ]]; then
            IFS='/' read -r os arch <<< "$platform"
            build_binary "$os" "$arch" "client" || true
            build_binary "$os" "$arch" "server" || true
        fi
    done
}

# 清理
clean() {
    log_info "Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
    log_info "Clean complete!"
}

# 显示帮助
show_help() {
    echo "HysterGuard Build Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all      Build for all supported platforms"
    echo "  current  Build for current platform only"
    echo "  linux    Build for Linux platforms only"
    echo "  clean    Clean build directory"
    echo "  help     Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  VERSION  Set version string (default: 0.1.0)"
}

# 主函数
main() {
    cd "${PROJECT_ROOT}"
    
    case "${1:-current}" in
        all)
            build_all
            ;;
        current)
            build_current
            ;;
        linux)
            build_linux
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
