@echo off
REM Socket Sender - Cross-Platform Build Script for Windows
REM Bu script projeyi Windows, Linux ve macOS için derler

setlocal enabledelayedexpansion

REM Proje bilgileri
set PROJECT_NAME=socketSender
set BUILD_DIR=build
set MAIN_FILE=main.go

REM Versiyon bilgisi (git varsa)
for /f "tokens=*" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
if "%VERSION%"=="" set VERSION=dev

REM Build dizinini oluştur
echo 📦 Build dizini oluşturuluyor...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Build sayacı
set BUILD_COUNT=0
set FAILED_BUILDS=0

echo.
echo ╔════════════════════════════════════════╗
echo ║   Socket Sender - Build Script         ║
echo ╚════════════════════════════════════════╝
echo.
echo Versiyon: %VERSION%
go version
echo.

REM Linux builds
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo 🐧 Linux Builds
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
call :build linux amd64 ""
call :build linux 386 ""
call :build linux arm64 ""
call :build linux arm ""

REM Windows builds
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo 🪟 Windows Builds
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
call :build windows amd64 .exe
call :build windows 386 .exe
call :build windows arm64 .exe

REM macOS builds
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo 🍎 macOS Builds
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
call :build darwin amd64 ""
call :build darwin arm64 ""

REM Özet
echo.
echo ╔════════════════════════════════════════╗
echo ║           Build Özeti                 ║
echo ╚════════════════════════════════════════╝
echo.
echo ✓ Başarılı: %BUILD_COUNT%
if %FAILED_BUILDS% gtr 0 (
    echo ✗ Başarısız: %FAILED_BUILDS%
)
echo.
echo 📁 Build dosyaları: %BUILD_DIR%\
echo.
echo ✨ Build tamamlandı!
goto :eof

REM Build fonksiyonu
:build
set OS=%1
set ARCH=%2
set EXT=%3

if "%OS%"=="windows" (
    set OUTPUT_NAME=%PROJECT_NAME%.exe
) else (
    set OUTPUT_NAME=%PROJECT_NAME%
)

set OUTPUT_PATH=%BUILD_DIR%\%PROJECT_NAME%-%OS%-%ARCH%%EXT%

echo 🔨 Derleniyor: %OS%/%ARCH%...
set GOOS=%OS%
set GOARCH=%ARCH%
go build -ldflags "-s -w -X main.version=%VERSION%" -o "%OUTPUT_PATH%" %MAIN_FILE%

if %ERRORLEVEL% equ 0 (
    echo ✓ Başarılı: %OUTPUT_PATH%
    set /a BUILD_COUNT+=1
) else (
    echo ✗ Başarısız: %OS%/%ARCH%
    set /a FAILED_BUILDS+=1
)
echo.
goto :eof

