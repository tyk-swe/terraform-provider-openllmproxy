#!/usr/bin/env bash
set -euo pipefail

# Qualification pins real CLIs and verifies each published archive checksum.
root=$(cd "$(dirname "$0")/.." && pwd)
tools="$root/.local/tools"
mkdir -p "$tools"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
for tool in terraform tofu; do
  if [[ "$tool" == terraform ]]; then
    version=1.16.5
    base="https://releases.hashicorp.com/terraform/$version"
    archive="terraform_${version}_linux_amd64.zip"
    checksums="terraform_${version}_SHA256SUMS"
  else
    version=1.13.1
    base="https://github.com/opentofu/opentofu/releases/download/v$version"
    archive="tofu_${version}_linux_amd64.zip"
    checksums="tofu_${version}_SHA256SUMS"
  fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/$archive" -o "$scratch/$archive"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/$checksums" -o "$scratch/$checksums"
  python3 - "$scratch" "$archive" "$checksums" "$tools" "$tool" <<'PY'
import hashlib, pathlib, sys, zipfile
directory, archive, checksums, output, tool = sys.argv[1:]
directory = pathlib.Path(directory)
entries = [line.split() for line in (directory / checksums).read_text().splitlines()]
matches = [entry[0] for entry in entries if len(entry) == 2 and entry[1].lstrip('*') == archive]
if len(matches) != 1 or hashlib.sha256((directory / archive).read_bytes()).hexdigest() != matches[0]:
    raise SystemExit('tool archive checksum mismatch')
with zipfile.ZipFile(directory / archive) as package:
    binary = pathlib.Path(output) / tool
    binary.write_bytes(package.read(tool))
    binary.chmod(0o755)
PY
done
