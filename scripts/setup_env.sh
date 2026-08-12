#!/bin/bash
# RISKX — sandbox environment setup (one-time)
# Idempotent: safe to re-run.
set -euo pipefail

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Install golangci-lint (pinned version — do not float)
GOLANGCI_VERSION="v2.1.6"
if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "[setup] installing golangci-lint ${GOLANGCI_VERSION} ..."
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$HOME/go/bin" "${GOLANGCI_VERSION}"
fi

echo "[setup] go: $(go version)"
echo "[setup] golangci-lint: $(golangci-lint --version | head -1)"
echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> "$HOME/.zshrc"
echo "[setup] done"
