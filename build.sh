#!/bin/bash

# Socket Sender - Cross-Platform Build Script
# Bu script projeyi Windows, Linux ve macOS için derler

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Proje bilgileri
PROJECT_NAME="socketSender"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR="build"
MAIN_FILE="main.go"

# Build dizinini oluştur
echo -e "${BLUE}📦 Build dizini oluşturuluyor...${NC}"
mkdir -p "$BUILD_DIR"

# Build sayacı
BUILD_COUNT=0
FAILED_BUILDS=0

# Build fonksiyonu
build() {
    local os=$1
    local arch=$2
    local ext=$3
    local output_name="${PROJECT_NAME}"
    
    if [ "$os" = "windows" ]; then
        output_name="${PROJECT_NAME}.exe"
    fi
    
    local output_path="${BUILD_DIR}/${PROJECT_NAME}-${os}-${arch}${ext}"
    
    echo -e "${YELLOW}🔨 Derleniyor: ${os}/${arch}...${NC}"
    
    GOOS=$os GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" -o "$output_path" "$MAIN_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Başarılı: ${output_path}${NC}"
        BUILD_COUNT=$((BUILD_COUNT + 1))
        
        # Dosya boyutunu göster
        local size=$(du -h "$output_path" | cut -f1)
        echo -e "  📏 Boyut: ${size}"
    else
        echo -e "${RED}✗ Başarısız: ${os}/${arch}${NC}"
        FAILED_BUILDS=$((FAILED_BUILDS + 1))
    fi
    echo ""
}

# Build başlangıcı
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Socket Sender - Build Script       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Versiyon: ${VERSION}${NC}"
echo -e "${BLUE}Go Versiyonu: $(go version)${NC}"
echo ""

# Linux builds
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🐧 Linux Builds${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
build "linux" "amd64" ""
build "linux" "386" ""
build "linux" "arm64" ""
build "linux" "arm" ""

# Windows builds
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🪟 Windows Builds${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
build "windows" "amd64" ".exe"
build "windows" "386" ".exe"
build "windows" "arm64" ".exe"

# macOS builds
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🍎 macOS Builds${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
build "darwin" "amd64" ""
build "darwin" "arm64" ""

# Özet
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Build Özeti                 ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}✓ Başarılı: ${BUILD_COUNT}${NC}"

if [ $FAILED_BUILDS -gt 0 ]; then
    echo -e "${RED}✗ Başarısız: ${FAILED_BUILDS}${NC}"
fi

echo ""
echo -e "${BLUE}📁 Build dosyaları: ${BUILD_DIR}/${NC}"
echo ""

# Dosya listesi
if [ $BUILD_COUNT -gt 0 ]; then
    echo -e "${YELLOW}Oluşturulan dosyalar:${NC}"
    ls -lh "$BUILD_DIR" | grep "$PROJECT_NAME" | awk '{print "  " $9 " (" $5 ")"}'
    echo ""
    
    # SHA256 checksum dosyaları oluştur
    echo -e "${BLUE}🔐 SHA256 checksum dosyaları oluşturuluyor...${NC}"
    cd "$BUILD_DIR"
    for file in ${PROJECT_NAME}-*; do
        if [ -f "$file" ]; then
            sha256sum "$file" > "${file}.sha256"
            echo -e "${GREEN}✓ ${file}.sha256${NC}"
        fi
    done
    cd ..
    echo ""
fi

echo -e "${GREEN}✨ Build tamamlandı!${NC}"

