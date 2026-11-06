#!/bin/sh
# Generates the dpkg version comparison corpus (P2-S09) with the reference tool, dpkg --compare-versions.
#
#   script/dpkg-corpus.sh           rewrite the expected column of spec/fixtures/dpkg/compare-versions.tsv
#   script/dpkg-corpus.sh --check   fail if any expected value differs from what this dpkg says
#
# CI runs --check inside debian:13, so the committed results are Debian 13's dpkg. Each row is
# left<TAB>right<TAB>expected, where expected is -1, 0, or 1 (left lt, eq, gt right), or invalid when dpkg
# refuses either version with an error (a warning still compares). Lines starting with # are kept as they are.
# Versions in the corpus contain no whitespace or tabs, and do not start with "-" (dpkg would read an option).
set -eu

cd "$(dirname "$0")/.."
corpus=spec/fixtures/dpkg/compare-versions.tsv
mode=${1:-write}
tab=$(printf '\t')

compare() {
  if dpkg --compare-versions "$1" lt "$2" 2>/dev/null; then echo -1; return; fi
  status=0
  dpkg --compare-versions "$1" eq "$2" 2>/dev/null || status=$?
  case $status in
    0) echo 0 ;;
    1) echo 1 ;;
    *) echo invalid ;;
  esac
}

out=$(mktemp)
trap 'rm -f "$out"' EXIT
differences=0
rows=0
while IFS= read -r line || [ -n "$line" ]; do
  case $line in
    '#'* | '')
      printf '%s\n' "$line" >>"$out"
      continue
      ;;
  esac
  left=${line%%"$tab"*}
  rest=${line#*"$tab"}
  right=${rest%%"$tab"*}
  expected=${rest#*"$tab"}
  [ "$expected" = "$rest" ] && expected=
  actual=$(compare "$left" "$right")
  rows=$((rows + 1))
  if [ "$mode" = --check ] && [ "$actual" != "$expected" ]; then
    echo "dpkg-corpus: $left vs $right: corpus says '$expected', dpkg $(dpkg-query -W -f='${Version}' dpkg) says '$actual'" >&2
    differences=$((differences + 1))
  fi
  printf '%s\t%s\t%s\n' "$left" "$right" "$actual" >>"$out"
done <"$corpus"

if [ "$mode" = --check ]; then
  if [ "$differences" -gt 0 ]; then
    echo "dpkg-corpus: $differences of $rows rows differ" >&2
    exit 1
  fi
  echo "dpkg-corpus: all $rows rows agree with dpkg $(dpkg-query -W -f='${Version}' dpkg)"
else
  cp "$out" "$corpus"
  echo "dpkg-corpus: wrote $rows rows with dpkg $(dpkg-query -W -f='${Version}' dpkg)"
fi
