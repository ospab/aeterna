#!/usr/bin/env bash
# checksum.sh — generate SHA-256, SHA-512 and MD5 checksums for a file
# Usage: bash scripts/checksum.sh <file> [output-dir]

set -euo pipefail

# ── args ────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <file> [output-dir]" >&2
    exit 1
fi

FILE="$1"
if [[ ! -f "$FILE" ]]; then
    echo "Error: file not found: $FILE" >&2
    exit 1
fi

BASENAME="$(basename "$FILE")"
OUTDIR="${2:-$(dirname "$FILE")}"
OUTFILE="$OUTDIR/$BASENAME.checksums"
GENERATED="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
SIZE="$(du -h "$FILE" | cut -f1)"

mkdir -p "$OUTDIR"

# ── compute ──────────────────────────────────────────────────────────────────
SHA256="$(sha256sum "$FILE" | awk '{print $1}')"
SHA512="$(sha512sum "$FILE" | awk '{print $1}')"
MD5="$(md5sum    "$FILE" | awk '{print $1}')"

# ── write ────────────────────────────────────────────────────────────────────
cat > "$OUTFILE" <<EOF
# Checksums for: $BASENAME
# Size:          $SIZE
# Generated:     $GENERATED

SHA-256  $SHA256  $BASENAME
SHA-512  $SHA512  $BASENAME
MD5      $MD5  $BASENAME
EOF

# ── print ────────────────────────────────────────────────────────────────────
echo ""
echo "  File      : $BASENAME"
echo "  Size      : $SIZE"
echo "  Generated : $GENERATED"
echo ""
echo "  SHA-256   $SHA256"
echo "  SHA-512   $SHA512"
echo "  MD5       $MD5"
echo ""
echo "  Written to: $OUTFILE"
echo ""
echo "  Verify with:"
echo "    sha256sum -c $OUTFILE"
