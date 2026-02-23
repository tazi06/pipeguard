#!/bin/sh
# PipeGuard Installer
# Usage: curl -sfL https://raw.githubusercontent.com/tazi06/pipeguard/main/install.sh | sh
#
# Environment variables:
#   PIPEGUARD_VERSION  - specific version to install (default: latest)
#   PIPEGUARD_DIR      - install directory (default: /usr/local/bin)
#
# Copyright (C) 2025 yhakkache — AGPL-3.0

set -e

REPO="tazi06/pipeguard"
BINARY="pipeguard"
INSTALL_DIR="${PIPEGUARD_DIR:-/usr/local/bin}"

# --- colors (disabled if not a terminal) ---
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

info()  { printf "${CYAN}[INFO]${RESET}  %s\n" "$1"; }
ok()    { printf "${GREEN}[OK]${RESET}    %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${RESET}  %s\n" "$1"; }
fail()  { printf "${RED}[ERROR]${RESET} %s\n" "$1"; exit 1; }

# --- detect OS ---
detect_os() {
    OS="$(uname -s)"
    case "$OS" in
        Linux*)   OS="linux" ;;
        Darwin*)  OS="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *) fail "Unsupported operating system: $OS" ;;
    esac
}

# --- detect architecture ---
detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) fail "Unsupported architecture: $ARCH" ;;
    esac
}

# --- get latest version from GitHub API ---
get_latest_version() {
    if [ -n "$PIPEGUARD_VERSION" ]; then
        VERSION="$PIPEGUARD_VERSION"
        info "Using specified version: $VERSION"
        return
    fi

    info "Fetching latest version..."
    VERSION=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')

    if [ -z "$VERSION" ]; then
        fail "Could not determine latest version. Set PIPEGUARD_VERSION manually."
    fi

    info "Latest version: v${VERSION}"
}

# --- download and install ---
install() {
    detect_os
    detect_arch
    get_latest_version

    # build download URL
    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
    fi
    FILENAME="${BINARY}_${VERSION}_${OS}_${ARCH}.${EXT}"
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${FILENAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"

    info "Downloading ${BOLD}${FILENAME}${RESET}..."
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    curl -sfL "$URL" -o "${TMP_DIR}/${FILENAME}" || fail "Download failed: ${URL}"
    ok "Downloaded successfully"

    # verify checksum
    info "Verifying checksum..."
    curl -sfL "$CHECKSUM_URL" -o "${TMP_DIR}/checksums.txt" || warn "Could not download checksums (skipping verification)"

    if [ -f "${TMP_DIR}/checksums.txt" ]; then
        EXPECTED=$(grep "${FILENAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            if command -v sha256sum > /dev/null 2>&1; then
                ACTUAL=$(sha256sum "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
            elif command -v shasum > /dev/null 2>&1; then
                ACTUAL=$(shasum -a 256 "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
            else
                warn "No sha256sum/shasum found, skipping checksum verification"
                ACTUAL="$EXPECTED"
            fi

            if [ "$EXPECTED" != "$ACTUAL" ]; then
                fail "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}"
            fi
            ok "Checksum verified"
        else
            warn "Checksum entry not found for ${FILENAME}"
        fi
    fi

    # extract
    info "Extracting..."
    if [ "$EXT" = "tar.gz" ]; then
        tar -xzf "${TMP_DIR}/${FILENAME}" -C "${TMP_DIR}"
    else
        unzip -q "${TMP_DIR}/${FILENAME}" -d "${TMP_DIR}"
    fi

    # install binary
    if [ ! -d "$INSTALL_DIR" ]; then
        mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
    fi

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
        chmod +x "${INSTALL_DIR}/${BINARY}"
    else
        info "Need sudo to install to ${INSTALL_DIR}"
        sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY}"
    fi

    ok "Installed ${BOLD}pipeguard v${VERSION}${RESET} to ${INSTALL_DIR}/${BINARY}"

    # verify installation
    if command -v pipeguard > /dev/null 2>&1; then
        echo ""
        printf "  ${BOLD}pipeguard${RESET} is ready. Run:\n"
        echo ""
        printf "    ${CYAN}pipeguard scan .${RESET}\n"
        echo ""
    else
        warn "${INSTALL_DIR} is not in your PATH. Add it:"
        printf "    export PATH=\"${INSTALL_DIR}:\$PATH\"\n"
    fi
}

# --- main ---
printf "\n"
printf "  ${BOLD}PipeGuard Installer${RESET}\n"
printf "  Pipeline Security & Quality Scanner\n"
printf "  https://github.com/${REPO}\n"
printf "\n"

install
