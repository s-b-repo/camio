#!/usr/bin/env bash
# audit-bad-patterns.sh — run the docs/BAD_PATTERNS.md regex matrix against
# every .rs file under the source tree.
#
# Usage:
#   scripts/audit-bad-patterns.sh                     # full report to stdout
#   scripts/audit-bad-patterns.sh --strict            # exit non-zero on A/B/C/L/M/N/O hits
#   scripts/audit-bad-patterns.sh --section A         # run only one section
#   scripts/audit-bad-patterns.sh --section A --verbose  # ... and list file:line for each hit
#   scripts/audit-bad-patterns.sh --files <list>      # restrict to newline-separated file list
#   scripts/audit-bad-patterns.sh --src crates        # override source root (default: src, else crates)
#   scripts/audit-bad-patterns.sh --zero "C L M"      # exit non-zero if those sections have any hit
#
# Sections (from docs/BAD_PATTERNS.md):
#   A: Panicking error handling       B: Silent error swallowing
#   C: Lint suppression               D: Panic vectors (index/slice)
#   E: Numeric / unsafe               F: Async / blocking
#   G: Logging                        H: HTTP layer
#   I: Iterator glitches              J: Style / secrets
#   K: (reserved)                     L: Crypto
#   M: SQL & command injection        N: UB / concurrency
#   O: Performance                    P: API hygiene
#
# Findings reported here are candidate smells, not confirmed bugs: every hit
# must be read in context before it is treated as a defect. Excuse a false
# positive with `// audit-allow: <SECTION><n>` on the same line or the line
# above it. Test code (`#[cfg(test)]` and tests/ files) is excluded by
# default; pass --include-tests to audit it too.

set -u
set -o pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

STRICT=0
ONLY_SECTION=""
FILE_LIST=""
VERBOSE=0
INCLUDE_TESTS=0
ZERO_SECTIONS=""
SRC_DIR="${CAMIO_SRC_DIR:-}"
[ -n "$SRC_DIR" ] || SRC_DIR="src"
[ -d "$SRC_DIR" ] || SRC_DIR="crates"

usage() { sed -n '1!s/^# \{0,1\}//p' "$0"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --strict)        STRICT=1; shift ;;
        --verbose)       VERBOSE=1; shift ;;
        --include-tests) INCLUDE_TESTS=1; shift ;;
        --zero)          ZERO_SECTIONS="${2:-}"; shift 2 ;;
        --section)       ONLY_SECTION="${2:-}"; shift 2 ;;
        --src)           SRC_DIR="${2:-}"; shift 2 ;;
        --files)         FILE_LIST="${2:-}"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

ALL_SECTION_LABELS="A B C D E F G H I J L M N O P"
if [ -n "$ONLY_SECTION" ] && ! printf '%s\n' $ALL_SECTION_LABELS \
        | grep -qx -- "$ONLY_SECTION"; then
    echo "unknown section: $ONLY_SECTION (expected one of: $ALL_SECTION_LABELS)" >&2
    exit 2
fi
for s in $ZERO_SECTIONS; do
    if ! printf '%s\n' $ALL_SECTION_LABELS | grep -qx -- "$s"; then
        echo "unknown section in --zero list: $s" >&2
        exit 2
    fi
done

if [ -n "$FILE_LIST" ]; then
    if [ ! -f "$FILE_LIST" ]; then
        echo "file list $FILE_LIST does not exist" >&2
        exit 2
    fi
    ALL_RS=$(grep -v '^[[:space:]]*$' "$FILE_LIST" | while IFS= read -r f; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done)
else
    if [ ! -d "$SRC_DIR" ]; then
        echo "source directory $SRC_DIR does not exist" >&2
        exit 2
    fi
    # NUL-delimited: safe for paths containing spaces or shell metacharacters.
    ALL_RS=$(find "$SRC_DIR" -name '*.rs' -type f -print0 | tr '\0' '\n')
fi

N_FILES=0
[ -n "$ALL_RS" ] && N_FILES=$(printf '%s\n' "$ALL_RS" | wc -l | tr -d ' ')

# What grep scans: the explicit file list when one was given, otherwise the
# source root (recursively). Keeping this as an array means a `--files` run
# really is restricted to those files — passing the root instead silently
# audits the whole tree.
GREP_TARGETS=()
if [ -n "$FILE_LIST" ]; then
    while IFS= read -r f; do
        [ -n "$f" ] && GREP_TARGETS+=("$f")
    done <<EOF
$ALL_RS
EOF
else
    GREP_TARGETS=("$SRC_DIR")
fi

# Read the tree once, then let grep scan it. -I skips binaries, --exclude-dir
# keeps generated/vendored code out of the audit.
GREP_ARGS=(-rEnI --include='*.rs' --exclude-dir=target --exclude-dir=vendor
           --exclude-dir=node_modules --exclude-dir='.git')

# Lines that must never count as hits:
#   * whole-line comments (//, ///, //!)
#   * lines that are only an opening block comment
#   * the code line a `// audit-allow: <SECTION><n>` marker excuses, whether the
#     marker sits on that same line or on the line above it
# (`[*]` rather than `\*`: the pattern is compiled as an awk dynamic regex, where
#  a bare backslash-star is a warning.)
FILTER='^[[:space:]]*(//|///|//!|[*]|/[*])'

# Test code is excluded by default: `#[cfg(test)]` modules account for the bulk
# of raw hits (unwrap/assert/expect are idiomatic there) and would make
# --strict fail on every repository that has tests. Pass --include-tests to
# count it. A file is test-only if it lives under tests/ or is named
# test_*/*_test; otherwise its test region starts at the first #[cfg(test)].
#
# MAP_FILE carries one record per line:
#   TEST <file> <line>   first line of that file's test region
#   SKIP <file> <line>   line excused by an audit-allow marker: the marker line
#                        itself and the line that follows it
# SKIP records are precomputed because a marker on the line *above* a hit never
# reaches the filter — it is a comment, so the pattern grep does not emit it.
MAP_FILE=$(mktemp) || exit 3
trap 'rm -f "$MAP_FILE"' EXIT
if [ "$INCLUDE_TESTS" = "0" ]; then
    printf '%s\n' "$ALL_RS" | while IFS= read -r f; do
        [ -f "$f" ] || continue
        if printf '%s' "/$f" | grep -qE '/(tests/|test_[^/]*|[^/]*_test)\.rs$'; then
            printf 'TEST %s 0\n' "$f" >> "$MAP_FILE"
        else
            start=$(grep -n -m1 -E '^[[:space:]]*#\[cfg\(test\)\]' "$f" 2>/dev/null \
                    | cut -d: -f1)
            [ -n "$start" ] && printf 'TEST %s %s\n' "$f" "$start" >> "$MAP_FILE"
        fi
    done
fi
printf '%s\n' "$ALL_RS" | while IFS= read -r f; do
    [ -f "$f" ] || continue
    grep -n 'audit-allow' "$f" 2>/dev/null | cut -d: -f1 \
        | while IFS= read -r ln; do
              # A marker excuses the statement it introduces. A statement can
              # span several lines, so the marker covers from the next line up
              # to and including the first line that ends a statement.
              span=$(awk -v from="$ln" 'NR >= from { print; if ($0 ~ /[;?][[:space:]]*$/) exit }' "$f" | wc -l)
              # The marker's own line too, so a trailing `// audit-allow: …`
              # on the statement it annotates still excuses that statement.
              i=0
              while [ "$i" -le "$span" ]; do
                  printf 'SKIP %s %s\n' "$f" "$((ln + i))" >> "$MAP_FILE"
                  i=$((i + 1))
              done
          done
done

# Filter grep's `path:lineno:text` output down to real production hits: drop
# comment-only lines, lines excused by an audit-allow marker, and #[cfg(test)]
# regions.
prod_filter() {
    awk -v tests="$INCLUDE_TESTS" -v filter="$FILTER" '
        NR == FNR {                       # first pass: the map file
            if ($1 == "TEST") tstart[$2] = $3; else skip[$2 " " $3] = 1
            next
        }
        {
            # grep -n emits `path:lineno:text`; the text is everything after the
            # second colon. Filters must test the *text*, not the whole line —
            # testing the whole line makes every comment and doc-comment line
            # look like code.
            p = $0; sub(/:.*$/, "", p)
            rest = substr($0, length(p) + 2)
            ln = rest; sub(/:.*$/, "", ln)
            text = substr(rest, length(ln) + 2)
            if ((p " " ln) in skip) next
            if (text ~ filter) next
            if (tests != "1" && (p in tstart) && (ln + 0) >= (tstart[p] + 0)) next
            print
        }' "$MAP_FILE" -
}

# ---- pattern arrays ------------------------------------------------------

A=(  # Panicking error handling
    '\.unwrap\(\)'  '\.expect\('  '\.unwrap_or_default\(\)'
    '\.parse\(\)\.unwrap\(\)'  '\.parse::<[^>]+>\(\)\.unwrap\(\)'
    '\.try_into\(\)\.unwrap\(\)'
    '\.first\(\)\.unwrap\(\)'  '\.last\(\)\.unwrap\(\)'
    '\.next\(\)\.unwrap\(\)'
    '\.iter\(\)\.[a-z_]+\([^)]*\)\.unwrap\(\)'
    '\.chars\(\)\.next\(\)\.unwrap\(\)'
    '\.split\([^)]*\)\.next\(\)\.unwrap\(\)'
    '\.position\([^)]*\)\.unwrap\(\)'
    '\.iter\(\)\.find\([^)]*\)\.unwrap\(\)'
    '\.read_to_string\([^)]*\)\.unwrap\(\)'
    '\.lock\(\)\.unwrap\(\)'
    '\.expect_err\('  '\.unwrap_err\('
    'panic!\('  'unreachable!\('  'todo!\('  'unimplemented!\('
    '\bassert!\('  '\bassert_eq!\('  '\bassert_ne!\('
)
B=(  # Silent error swallowing
    'Err\(_\)'  'Err\(_[a-zA-Z]\w*\)'  'if let Err\(_'
    'if let Ok\('  'let\s+_\s*='  'let\s+_[a-zA-Z]\w*\s*=.*\.await'
    '\.map_err\(\|_\|'  '\.or_else\(\|_\|'
    '\.to_str\(\)\.ok\(\)'  '\.json\([^)]*\)\.await\.ok\(\)'
    '\.send\(\)\.await\.ok\(\)'  '\.text\(\)\.await\.ok\(\)'
    # B10: underscore-prefixed function parameter (bypass unused-parameter warning)
    'fn\s+\w+\([^)]*\b_\w+\s*:\s*[^)]*\)'
    # B11: underscore-prefixed variable binding (bypass unused-variable warning)
    'let\s+_\w+\s*='
)
C=(  # Lint suppression
    '#\[allow\('  '#\[deny\('  '#\[ignore\b'
)
D=(  # Panic vectors (index/slice)
    '\b[a-zA-Z_]\w*\[[0-9]+\][^=]'
    '\&[a-zA-Z_]\w*\[\.\.\w+\]'
    '\&[a-zA-Z_]\w*\[\w+\.\.\]'
    '\&[a-zA-Z_]\w*\[\w+\.\.\w+\]'
    '\.split_at\('  '\.chars\(\)\.nth\('
)
E=(  # Numeric / unsafe
    '\bas\s+u8\b'  '\bas\s+i8\b'
    '\bas\s+u16\b'  '\bas\s+i16\b'
    '\bas\s+u32\b'  '\bas\s+i32\b'
    '\bas\s+u64\b'  '\bas\s+i64\b'
    '\bas\s+usize\b'  '\bas\s+isize\b'
    '\bas\s+f32\b'  '\bas\s+f64\b'
    '\bas\s+\*const\b'  '\bas\s+\*mut\b'
    '\btransmute\('  '\bextern\s+"C"'
    '\bunsafe\s*\{'  '\bunsafe\s+fn\b'
)
F=(  # Async / blocking
    'std::thread::sleep'  'std::process::Command'
    'std::fs::File'  'std::fs::read\b'  'std::fs::write\b'
    'std::net::TcpStream'  'std::net::UdpSocket'  'std::io::stdin'
)
G=(  # Logging
    '\bdbg!\('
    'format!\(.*"\{:\?\}".*\b[eE]rr\b'
    '\.context\(""\)'  '\.context\("\?"\)'
)
H=(  # HTTP layer
    'reqwest::Client::new\(\)'  'reqwest::Client::builder\(\)'
    '\.send\(\)\.await\?[^.]'  '\.text\(\)\.await\?[^.]'
    'format!\("\{:\?\}", \w+\)\.contains\('
)
I=(  # Iterator glitches
    '\.collect::<Result<Vec<_>,\s*_>>\(\)\.unwrap'
    '\.zip\([^)]*\)\.unwrap'
)
J=(  # Style / secrets
    '== ""'  '\.len\(\) == 0'  '\.len\(\) > 0'
    'String::from\(format!'
    '\.clone\(\)\s*\.clone'  '\.to_string\(\)\s*\.to_string'
    'XXXXXX|TODO|FIXME|HACK\b'
    'Bearer\s+[A-Za-z0-9_.-]{40,}'
    'sk-[A-Za-z0-9]{20,}'  'AKIA[A-Z0-9]{16}'
    '"admin"\s*,\s*"admin"'  '"root"\s*,\s*"root"'
    'Box<dyn'
    # J7: underscore import to bypass unused_crate_dependencies
    'use\s+\w+\s+as\s+_;'
    # J8: extern crate in edition 2024 to bypass unused-dep warning
    '^extern\s+crate\s+'
    # J9: &*format!(...) temporary drop — creates dangling reference
    '&\*format!\('
)
L=(  # Crypto
    '\bmd5::compute\b|\bmd5::Md5\b'
    '\bsha1::Sha1\b|use sha1::'
    '\bdes::Des\b|\b3des\b|TripleDES'
    'rand::thread_rng\(\)'  'rand::random\(\)'
    '\bRC4\b|rc4::'  'aes_128_ecb|aes-128-ecb|Ecb'
)
M=(  # Injection
    'format!\("SELECT[^"]*\{'  'format!\("INSERT[^"]*\{'
    'format!\("UPDATE[^"]*\{'  'format!\("DELETE[^"]*\{'
    'std::process::Command::new\("/bin/sh"\)'
    'std::process::Command::new\("sh"\)'
    '\.arg\("-c"\).*format!'
)
N=(  # UB / concurrency
    '\bstatic\s+mut\b'  'std::mem::transmute'  'std::mem::forget'
    'std::mem::uninitialized'  'std::mem::zeroed'
    'std::ptr::read'  'std::ptr::write'
    'Result<\(\), String>'  'Result<.*,\s*String>'
)
O=(  # Performance
    '\.iter\(\)\.count\(\)'  '\.collect::<\(\)>\(\)'
    '\.iter\(\)\.map\(\|\w+\|\s*\w+\.clone\(\)\)\s*\.collect'
    '\.to_string\(\)\.as_str\(\)'
    'Vec::with_capacity\(0\)'  'String::with_capacity\(0\)'
    'Regex::new\(.*\)\.unwrap'
    'Box::new\(.*Box::new'
)
P=(  # API hygiene
    '\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*"http'
    '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Pp]assword'
    '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Ss]ecret'
    '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Tt]oken'
)

declare -A SECTION_DESC=(
    [A]="Panicking error handling"   [B]="Silent error swallowing"
    [C]="Lint suppression"           [D]="Panic vectors (index/slice)"
    [E]="Numeric / unsafe"           [F]="Async / blocking"
    [G]="Logging"                    [H]="HTTP layer"
    [I]="Iterator glitches"          [J]="Style / secrets"
    [K]="(reserved)"                 [L]="Crypto"
    [M]="SQL & command injection"    [N]="UB / concurrency"
    [O]="Performance"                [P]="API hygiene"
)
SECTIONS_ALL=(A B C D E F G H I J L M N O P)
STRICT_SECTIONS=(A B C L M N O)

GRAND_TOTAL=0
GRAND_PATTERNS=0
GRAND_PATTERNS_HIT=0
STRICT_HITS=0
ZERO_HITS=0
MAX_DETAIL="${MAX_DETAIL:-25}"

run_section() {
    local label="$1"
    # Indirect array expansion (`${!label[@]}`) yields the array *keys*, not the
    # values, so bind a nameref to the section's pattern array instead.
    local -n arr="$label"
    local total=0 hit_pats=0 pats=${#arr[@]} c
    local -a lines=()
    GRAND_PATTERNS=$((GRAND_PATTERNS + pats))

    local n=0 p
    for p in "${arr[@]}"; do
        n=$((n + 1))
        # Count *matches*, not matching lines: `grep -o` emits one line per
        # occurrence, so `foo().unwrap().expect()` on a single line scores 2
        # rather than 1. Filtering happens before the re-count so comment,
        # audit-allow and test-region exclusions still apply.
        c=$(grep "${GREP_ARGS[@]}" "$p" "${GREP_TARGETS[@]}" 2>/dev/null \
            | prod_filter \
            | grep -oE -- "$p" 2>/dev/null | wc -l | tr -d ' ')
        : "${c:=0}"
        if [ "$c" -gt 0 ]; then
            total=$((total + c))
            hit_pats=$((hit_pats + 1))
            GRAND_PATTERNS_HIT=$((GRAND_PATTERNS_HIT + 1))
            lines+=("    [$c] $label$n /$p/")
            if [ "$VERBOSE" = "1" ]; then
                grep "${GREP_ARGS[@]}" "$p" "${GREP_TARGETS[@]}" 2>/dev/null \
                    | prod_filter \
                    | head -n "$MAX_DETAIL" \
                    | sed "s|^|        $label$n |"
            fi
        fi
    done

    GRAND_TOTAL=$((GRAND_TOTAL + total))
    printf "  %-2s %-32s : %5d hits across %2d/%-2d patterns\n" \
        "$label" "${SECTION_DESC[$label]}" "$total" "$hit_pats" "$pats"
    if [ "${#lines[@]}" -gt 0 ]; then
        printf '%s\n' "${lines[@]}"
    fi

    local s
    for s in "${STRICT_SECTIONS[@]}"; do
        if [ "$s" = "$label" ]; then
            STRICT_HITS=$((STRICT_HITS + total))
            break
        fi
    done
    for s in $ZERO_SECTIONS; do
        if [ "$s" = "$label" ]; then
            ZERO_HITS=$((ZERO_HITS + total))
            break
        fi
    done
    return 0
}

echo "============================================================"
echo "  BAD-PATTERN AUDIT  (matrix: docs/BAD_PATTERNS.md)"
echo "  $N_FILES file(s) under audit  root: $SRC_DIR"
echo "============================================================"
echo

if [ -z "$ONLY_SECTION" ]; then
    SECTIONS=("${SECTIONS_ALL[@]}")
else
    SECTIONS=("$ONLY_SECTION")
fi

for s in "${SECTIONS[@]}"; do
    if [ -z "${SECTION_DESC[$s]+x}" ]; then
        echo "unknown section: $s" >&2; exit 2
    fi
    run_section "$s"
    echo
done

echo "============================================================"
echo "  TOTALS"
echo "============================================================"
echo "  Patterns scanned       : $GRAND_PATTERNS"
echo "  Patterns with hits     : $GRAND_PATTERNS_HIT"
echo "  Total hit lines        : $GRAND_TOTAL"
echo "  Strict (A/B/C/L/M/N/O) : $STRICT_HITS"

if [ "$STRICT" = "1" ] && [ "$STRICT_HITS" -gt 0 ]; then
    echo "  RESULT                 : STRICT FAILURE — triage each hit before merge"
    exit 1
fi
if [ -n "$ZERO_SECTIONS" ] && [ "$ZERO_HITS" -gt 0 ]; then
    echo "  RESULT                 : ZERO-TOLERANCE FAILURE — $ZERO_HITS hit(s) in sections $ZERO_SECTIONS"
    exit 1
fi
echo "  RESULT                 : informational only (use --strict/--zero to gate)"