#!/usr/bin/env sh
# RISKX one-command installer (Linux / macOS)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/RajaMuhammadAwais/RISKX/main/install.sh | sh
#   RISKX_VERSION=v0.4.0 curl -fsSL https://raw.githubusercontent.com/RajaMuhammadAwais/RISKX/main/install.sh | sh   # specific release
#
# This script does exactly four things:
#   1. Resolves the latest stable RISKX release from GitHub (never prereleases,
#      unless RISKX_VERSION is set explicitly).
#   2. Downloads ONE binary and its checksums file from the official GitHub
#      Releases (HTTPS only, no git clone, no source tree).
#   3. Verifies the SHA-256 checksum of the downloaded binary.
#   4. Installs the verified binary to ~/.local/bin (or a user-chosen
#      RISKX_BIN_DIR), then prints the installed version.
#
# It never: hides the binary, obfuscates itself, downloads unrelated files,
# modifies unrelated user files, installs persistence, creates services or
# scheduled tasks, touches firewall rules, collects telemetry, or executes
# arbitrary remote commands.
set -e

REPO="RajaMuhammadAwais/RISKX"
BIN_NAME="riskx"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
RELEASES="https://api.github.com/repos/${REPO}/releases"

# --- OS detection ----------------------------------------------------------
case "$(uname -s)" in
  Linux)  OS="linux" ;;
  Darwin) OS="darwin" ;;
  *)
    echo "ERROR: unsupported operating system: $(uname -s)" >&2
    echo "RISKX provides pre-built binaries for Linux and macOS." >&2
    exit 1
    ;;
esac

# --- Architecture detection ------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "ERROR: unsupported CPU architecture: $(uname -m)" >&2
    echo "RISKX provides pre-built binaries for amd64 and arm64." >&2
    exit 1
    ;;
esac

# --- Resolve the release ---------------------------------------------------
if [ -z "${RISKX_VERSION}" ]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required but not found on PATH" >&2
    exit 1
  fi
  TAG=$(curl -fsSL "${RELEASES}/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/') || {
    echo "ERROR: cannot reach GitHub Releases API — check your internet connection" >&2
    exit 1
  }
  if [ -z "${TAG}" ]; then
    echo "ERROR: no release found for ${REPO}" >&2
    exit 1
  fi
else
  TAG="${RISKX_VERSION}"
fi
# Normalise: accept "v0.4.0" or "0.4.0"
case "${TAG}" in v*) ;; *) TAG="v${TAG}" ;; esac

VERSION="${TAG#v}"
ASSET="${BIN_NAME}_${OS}_${ARCH}"
URL_BASE="https://github.com/${REPO}/releases/download/${TAG}"
BINARY_URL="${URL_BASE}/${ASSET}"
CHECKSUMS_URL="${URL_BASE}/checksums.txt"

echo "==> Resolved release: ${TAG} (${OS}/${ARCH})"

# --- Download binary + checksums -------------------------------------------
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

BINARY="${TMPDIR_WORK}/${ASSET}"
if ! curl -fsSL -o "${BINARY}" "${BINARY_URL}"; then
  echo "ERROR: download failed: ${BINARY_URL}" >&2
  echo "The release ${TAG} may not exist for ${OS}/${ARCH}." >&2
  rm -f "${BINARY}"
  exit 1
fi

CHECKSUMS="${TMPDIR_WORK}/checksums.txt"
if ! curl -fsSL -o "${CHECKSUMS}" "${CHECKSUMS_URL}"; then
  echo "ERROR: download failed: ${CHECKSUMS_URL}" >&2
  echo "Checksum file missing for release ${TAG} — refusing to install." >&2
  rm -f "${BINARY}"
  exit 1
fi

# --- SHA-256 verification (the install aborts if this fails) ----------------
WANT="$(grep "${ASSET}" "${CHECKSUMS}" | awk '{print $1}')" || WANT=""
if [ -z "${WANT}" ]; then
  echo "ERROR: checksums.txt does not contain an entry for ${ASSET}" >&2
  echo "Checksum verification failed — downloaded file removed, not installed." >&2
  rm -f "${BINARY}"
  exit 1
fi

GOT="$(sha256sum "${BINARY}" | awk '{print $1}')" || GOT=""
if [ -z "${GOT}" ]; then
  GOT="$(shasum -a 256 "${BINARY}" | awk '{print $1}')"
fi

if [ "${GOT}" != "${WANT}" ]; then
  echo "ERROR: SHA-256 checksum verification failed for ${ASSET}" >&2
  echo "  expected: ${WANT}" >&2
  echo "  got:      ${GOT}" >&2
  echo "The downloaded binary has been removed and will NOT be installed." >&2
  rm -f "${BINARY}"
  exit 1
fi
echo "==> SHA-256 checksum verified"

# --- Install ---------------------------------------------------------------
if [ -n "${RISKX_BIN_DIR}" ]; then
  INSTALL_DIR="${RISKX_BIN_DIR}"
elif [ -d "$HOME/.local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  mkdir -p "$HOME/.local/bin"
  INSTALL_DIR="$HOME/.local/bin"
fi

chmod 755 "${BINARY}"
cp "${BINARY}" "${INSTALL_DIR}/${BIN_NAME}"
INSTALLED="${INSTALL_DIR}/${BIN_NAME}"

# --- PATH guidance ---------------------------------------------------------
add_path_hint() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      echo ""
      echo "${INSTALL_DIR} is not on your PATH. Add it with:"
      echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      if [ -f "$HOME/.profile" ]; then
        echo "or persist it in ~/.profile:"
        echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile"
      fi
      ;;
  esac
}

# --- Verify ----------------------------------------------------------------
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*)
    VER_OUT="$("${INSTALLED}" version 2>/dev/null)" || VER_OUT=""
    if [ -n "${VER_OUT}" ]; then
      echo ""
      echo "RISKX installed successfully."
      echo "  Binary: ${INSTALLED}"
      echo "  Version: $(echo "${VER_OUT}" | head -1)"
      exit 0
    fi
    add_path_hint
    echo "RISKX binary installed to ${INSTALLED} but could not be executed"
    echo "via the bare 'riskx' command; see the PATH hint above."
    exit 1
    ;;
  *)
    add_path_hint
    echo "RISKX binary installed to ${INSTALLED}."
    echo "Use the full path to verify: \"${INSTALLED}\" version"
    exit 0
    ;;
esac
