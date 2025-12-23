#!/bin/bash
set -euo pipefail

BIN=./ta152
DIR=testing
HEADER_SIZE=32


KEEP_FILES=(
    "keyfile_0.bin"
    "keyfile_1.bin"
    "og_src_img.jpg"
    "text.txt"
)

echo "[+] Smoke test (binary responds)"
$BIN || true

echo "[+] Image round-trip with IV"
cp "$DIR/og_src_img.jpg" "$DIR/img_work.jpg"
$BIN encrypt "$DIR/img_work.jpg" "$DIR/keyfile_0.bin" -iv
$BIN decrypt "$DIR/img_work.jpg.t152e" "$DIR/keyfile_0.bin"
cmp "$DIR/img_work.jpg" "$DIR/og_src_img.jpg"

echo "[+] Text setup"
cp "$DIR/text.txt" "$DIR/text_a.txt"
cp "$DIR/text.txt" "$DIR/text_b.txt"

echo "[+] Determinism test (no IV, same key)"
$BIN encrypt "$DIR/text_a.txt" "$DIR/keyfile_0.bin"
cp "$DIR/text_a.txt.t152e" "$DIR/out_ref.bin"

cp "$DIR/text.txt" "$DIR/text_a.txt"
$BIN encrypt "$DIR/text_a.txt" "$DIR/keyfile_0.bin"
cmp "$DIR/out_ref.bin" "$DIR/text_a.txt.t152e"

echo "[+] Key sensitivity (no IV)"
$BIN encrypt "$DIR/text_b.txt" "$DIR/keyfile_1.bin"
! cmp "$DIR/out_ref.bin" "$DIR/text_b.txt.t152e"

echo "[+] Decryption correctness (no IV)"
$BIN decrypt "$DIR/text_a.txt.t152e" "$DIR/keyfile_0.bin"
cmp "$DIR/text_a.txt" "$DIR/text.txt"

echo "[+] Non-determinism test (with IV)"
cp "$DIR/text.txt" "$DIR/text_a.txt"
cp "$DIR/text.txt" "$DIR/text_b.txt"

$BIN encrypt "$DIR/text_a.txt" "$DIR/keyfile_0.bin" -iv
$BIN encrypt "$DIR/text_b.txt" "$DIR/keyfile_0.bin" -iv

tail -c +$((HEADER_SIZE + 1)) "$DIR/text_a.txt.t152e" > "$DIR/payload_a.bin"
tail -c +$((HEADER_SIZE + 1)) "$DIR/text_b.txt.t152e" > "$DIR/payload_b.bin"

! cmp "$DIR/payload_a.bin" "$DIR/payload_b.bin"

echo "[+] Decryption correctness (with IV)"
$BIN decrypt "$DIR/text_a.txt.t152e" "$DIR/keyfile_0.bin"
$BIN decrypt "$DIR/text_b.txt.t152e" "$DIR/keyfile_0.bin"
cmp "$DIR/text_a.txt" "$DIR/text.txt"
cmp "$DIR/text_b.txt" "$DIR/text.txt"

echo "[+] Wrong-key decrypt test"
cp "$DIR/text.txt" "$DIR/text_a.txt"
$BIN encrypt "$DIR/text_a.txt" "$DIR/keyfile_0.bin" -iv
$BIN decrypt "$DIR/text_a.txt.t152e" "$DIR/keyfile_1.bin" || true
! cmp "$DIR/text_a.txt" "$DIR/text.txt"

echo "[+] All tests passed"

echo "[+] Cleanup: removing all generated files"
cd "$DIR"
shopt -s extglob
rm -f -- !("keyfile_0.bin"|"keyfile_1.bin"|"og_src_img.jpg"|"text.txt")
shopt -u extglob

echo "[+] Cleanup complete"
