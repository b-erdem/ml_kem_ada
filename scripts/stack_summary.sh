#!/usr/bin/env bash
#  Summarise per-function stack bounds emitted by gcc -fstack-usage.
#  Reads all .su files in obj/ and prints them sorted descending by
#  byte count, plus a total of all "static" frames (a useful bound
#  when computing worst-case stack via a hand-traced call chain).
#
#  Usage:
#      stack_summary.sh <library-dir>
#
#  e.g. ./stack_summary.sh ml_kem_ada
#       cd ml_kem_ada && ../scripts/stack_summary.sh .

set -euo pipefail

if [ $# -lt 1 ]; then
   echo "Usage: $0 <library-dir>" >&2
   exit 2
fi

dir="$1"
obj="${dir}/obj"

if [ ! -d "$obj" ]; then
   echo "No obj/ in $dir; build first with 'alr build'." >&2
   exit 1
fi

files=$(find "$obj" -name '*.su' -print)
if [ -z "$files" ]; then
   echo "No .su files in $obj. Add -fstack-usage to your GPR." >&2
   exit 1
fi

# Each .su line: "<file>:<line>:<col>:<NAME>\t<bytes>\t<kind>"
# Print: bytes  name  kind
{
   for f in $files; do cat "$f"; done
} \
   | awk -F'\t' '{
       # Field 1 has the qualified name; trim file:line:col: prefix.
       n = $1; sub(/^.*:/, "", n);
       printf "%8s  %-60s  %s\n", $2, n, $3;
     }' \
   | sort -k1 -n -r

echo "----"

total_static=$( { for f in $files; do cat "$f"; done } \
   | awk -F'\t' '$3 == "static" { sum += $2 } END { print sum + 0 }')
total_dyn=$( { for f in $files; do cat "$f"; done } \
   | awk -F'\t' '$3 ~ /dynamic/ { sum += $2 } END { print sum + 0 }')
echo "static total  : ${total_static} bytes"
echo "dynamic total : ${total_dyn} bytes (per-frame, not aggregated)"
