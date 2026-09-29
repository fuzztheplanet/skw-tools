#!/usr/bin/env bash
#
# get-bbscope.sh - pull Intigriti / YesWeHack program scopes via the bbscope
#                 Docker image and emit one normalized, queryable CSV.
#
# Only in-scope items from active, paying programs are listed.
#
# Upstream: https://github.com/sw33tLie/bbscope
#
set -o errexit
set -o nounset
set -o pipefail

readonly IMAGE="ghcr.io/sw33tlie/bbscope:latest"

# ASCII Unit Separator: bbscope's own -d delimiter. Chosen because it cannot
# occur in scope data, unlike "|" which appears in real targets such as
# *.contactallerg(y|ie).uzleuven.be
readonly SEP=$'\x1f'

OUTFILE="bbscope-scope.csv"
IT_TOKEN="${BBSCOPE_IT_TOKEN:-}"
YWH_TOKEN="${BBSCOPE_YWH_TOKEN:-}"
FORCE_PULL=0

log()  { printf '[*] %s\n' "$*" >&2; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE_EOF'
get-bbscope.sh - normalized bug bounty scope in CSV form

USAGE:
    get-bbscope.sh [-i <intigriti-token>] [-y <yeswehack-token>] [options]

A platform is queried only when its token is supplied: -i for Intigriti,
-y for YesWeHack. At least one of the two is required. Nothing is ever
fetched anonymously.

Only assets that are explicitly IN SCOPE are listed, and only for active
programs that pay monetary rewards. Out-of-scope items are never written,
and VDP / points-only programs are excluded.

The bbscope image is only pulled when it is not already present locally;
an existing image is reused as-is. Use -p to force a refresh.

OPTIONS:
    -i, --intigriti-token TOKEN   Intigriti bearer token (env: BBSCOPE_IT_TOKEN)
    -y, --yeswehack-token TOKEN   YesWeHack bearer token (env: BBSCOPE_YWH_TOKEN)
    -o, --output FILE             Output CSV (default: ./bbscope-scope.csv)
    -p, --pull-image              Refresh the image even if already present
    -h, --help                    This help

OUTPUT COLUMNS:
    platform,program,program_url,type,category,target,raw_target,description

    type         normalized kind, derived from the value itself:
                 wildcard, url, ip, cidr, android, ios, source_code,
                 ai_model, hardware, other
    category     the raw category bbscope reported, kept for reference
    target       normalized item, ready to feed to tooling
    raw_target   the untouched upstream string, so nothing is lost
    description  upstream description, whitespace-collapsed

    Note: type "other" means the upstream target was prose rather than a
    technical asset (e.g. "Any publicly facing asset"), not a testable host.

QUERY EXAMPLES:
    Every field is quoted and no field contains a newline, so splitting on
    '","' gives you columns 2..7 directly. Column 1 keeps a leading quote,
    so filter the platform with grep instead of awk.

    # every wildcard, bare
    awk -F'","' 'NR>1 && $4=="wildcard"{print $6}' bbscope-scope.csv

    # hosts to feed a resolver (wildcards + plain urls), deduped
    awk -F'","' 'NR>1 && ($4=="wildcard"||$4=="url"){print $6}' \
        bbscope-scope.csv | sed 's#/.*##; s/^\*\.//' | sort -u

    # Android package names on one platform
    grep '^"yeswehack",' bbscope-scope.csv | awk -F'","' '$4=="android"{print $6}'

    # IP ranges
    awk -F'","' 'NR>1 && ($4=="cidr"||$4=="ip"){print $6}' bbscope-scope.csv

    # everything for one program (column 2 is the platform's program slug)
    grep -i '","adobepublic","' bbscope-scope.csv

    # list the programs you pulled
    awk -F'","' 'NR>1{print $2}' bbscope-scope.csv | sort -u

    # with csvkit / miller, if you prefer a real CSV parser
    csvgrep -c type -m wildcard bbscope-scope.csv | csvcut -c program,target
    mlr --icsv --opprint filter '$type=="cidr"' then cut -f program,target \
        bbscope-scope.csv
USAGE_EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--intigriti-token) [[ $# -ge 2 ]] || die "$1 needs a value"; IT_TOKEN="$2"; shift 2 ;;
        -y|--yeswehack-token) [[ $# -ge 2 ]] || die "$1 needs a value"; YWH_TOKEN="$2"; shift 2 ;;
        -o|--output)          [[ $# -ge 2 ]] || die "$1 needs a value"; OUTFILE="$2"; shift 2 ;;
        -p|--pull-image)      FORCE_PULL=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        *)                    die "unknown argument: $1 (try --help)" ;;
    esac
done

if [[ -z "$IT_TOKEN" && -z "$YWH_TOKEN" ]]; then
    die "no tokens given: pass -i <intigriti-token> and/or -y <yeswehack-token> (see --help)"
fi

command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon (is it running, are you in the docker group?)"

# Resolve the output path against the calling directory before any cd.
case "$OUTFILE" in
    /*) ;;
    *)  OUTFILE="$PWD/$OUTFILE" ;;
esac
outdir="$(dirname -- "$OUTFILE")"
[[ -d "$outdir" ]] || die "output directory does not exist: $outdir"
[[ -w "$outdir" ]] || die "output directory is not writable: $outdir"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/bbscope.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    if [[ $FORCE_PULL -eq 1 ]]; then
        log "refreshing $IMAGE"
        docker pull --quiet "$IMAGE" >/dev/null 2>&1 \
            || warn "docker pull failed; using the existing local image"
    else
        log "using local image $IMAGE"
    fi
else
    log "$IMAGE not present locally - pulling it once"
    docker pull --quiet "$IMAGE" >/dev/null 2>&1 \
        || die "image $IMAGE is not present locally and could not be pulled"
    docker image inspect "$IMAGE" >/dev/null 2>&1 \
        || die "image $IMAGE is not present locally and could not be pulled"
fi

# ---------------------------------------------------------------------------
# normalize: \x1f-delimited "target cat description program_url" -> CSV rows
# ---------------------------------------------------------------------------
read -r -d '' NORMALIZE_AWK <<'AWK_EOF' || true
function trim(s)   { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
function squash(s) { gsub(/[[:space:]]+/, " ", s); return trim(s) }
function q(s)      { gsub(/"/, "\"\"", s); return "\"" s "\"" }

# Does this token look like a self-contained scope item? Used only to decide
# whether a whitespace-containing target is a list of items or just prose.
function is_item(s) {
    if (s == "" || s ~ /[[:space:]]/)                          return 0
    if (s ~ /^[0-9]{5,12}$/)                                   return 1  # App Store id
    if (s ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/)    return 1  # IPv4 (+CIDR)
    if (s ~ /^[0-9A-Fa-f:]*::?[0-9A-Fa-f:]*\/[0-9]{1,3}$/)     return 1  # IPv6 CIDR
    if (s ~ /^\*?\.?[A-Za-z0-9*_-]+(\.[A-Za-z0-9*_-]+)+(\/[^[:space:]]*)?$/) return 1
    return 0
}

function strip_scheme(s) { sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", s); return s }

# Lowercase only the host; paths and query strings stay case-sensitive.
function lc_host(s,   i, host, rest) {
    i = index(s, "/")
    if (i > 0) { host = substr(s, 1, i - 1); rest = substr(s, i) }
    else       { host = s;                   rest = "" }
    return tolower(host) rest
}

# Only values that are genuinely host/URL/IP shaped get rewritten; prose
# targets such as "Acrobat AI Assistant" must survive untouched.
function host_like(s) { return is_item(strip_scheme(s)) }
function norm_item(s,   t) {
    t = lc_host(strip_scheme(s))
    sub(/\/+$/, "", t)
    return t
}

# Play Store / App Store URLs carry the identifier we actually want.
function extract_app(cat, v,   t) {
    if (cat == "android") {
        if (v ~ /[?&]id=/) { t = v; sub(/^.*[?&]id=/, "", t); sub(/[&#].*$/, "", t); return t }
        return v
    }
    if (cat == "ios" || cat == "apple") {
        if (v ~ /\/id[0-9]+/) { t = v; sub(/^.*\/id/, "", t); sub(/[^0-9].*$/, "", t); return t }
        return v
    }
    return v
}

# bbscope's category is authoritative for the *kind* of asset; we only
# re-derive within the url/wildcard/other space, where it is often wrong
# (e.g. YesWeHack reports *.captcha-delivery.com as "url").
function classify(cat, v,   lv) {
    lv = tolower(v)
    if (cat == "android")                                  return "android"
    if (cat == "ios" || cat == "apple")                    return "ios"
    if (cat == "sourcecode" || cat == "source-code")       return "source_code"
    if (cat == "aimodel" || cat == "ai-model" || cat == "ai") return "ai_model"
    if (cat == "hardware")                                 return "hardware"
    if (cat == "cidr") {
        if (v ~ /\//) return "cidr"
        if (v ~ /^[0-9.]+$/ || v ~ /:/) return "ip"
        return "cidr"
    }
    if (v ~ /\*/)                                              return "wildcard"
    if (v ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}\/[0-9]{1,2}$/)       return "cidr"
    if (v ~ /^[0-9A-Fa-f:]*::?[0-9A-Fa-f:]*\/[0-9]{1,3}$/)     return "cidr"
    if (v ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/)                   return "ip"
    if (lv ~ /^(github|gitlab|bitbucket)\.(com|org)\//)        return "source_code"
    if (is_item(v))                                            return "url"
    return "other"
}

# app.intigriti.com/researcher/programs/adobe/adobepublic/detail -> adobepublic
# yeswehack.com/programs/sogexia                                -> sogexia
function program_of(url,   s, n, parts, i) {
    s = strip_scheme(url)
    sub(/[?#].*$/, "", s)
    sub(/\/+$/, "", s)
    n = split(s, parts, "/")
    for (i = n; i >= 1; i--)
        if (parts[i] != "" && parts[i] != "detail")
            return parts[i]
    return s
}

function emit(val,   t) {
    if (val == "") return
    # app identifiers are already extracted and are case-sensitive
    if (cat != "android" && cat != "ios" && cat != "apple" && host_like(val))
        val = norm_item(val)
    if (val == "") return
    t = classify(cat, val)
    print q(platform) "," q(prog) "," q(url) "," q(t) "," q(cat) "," \
          q(val) "," q(raw) "," q(desc)
}

BEGIN { FS = "\x1f"; OFS = ","; oos_dropped = 0 }

NF < 4 { next }

{
    raw  = $1
    cat  = tolower(trim($2))
    desc = squash($3)
    url  = trim($4)

    v = raw

    # bbscope is run without --oos, so nothing here should be marked
    # out-of-scope. This is a belt-and-braces filter: anything still
    # carrying an [OOS] marker is dropped rather than written out.
    if (v ~ /^[[:space:]]*\[(OOS|OUT OF SCOPE)\]/) { oos_dropped++; next }

    v = squash(v)

    # strip markdown noise: **bold**, `code`, <brackets>, [text](url)
    gsub(/\*\*/, "", v)
    gsub(/`/, "", v)
    if (v ~ /^<.*>$/) { sub(/^</, "", v); sub(/>$/, "", v) }
    if (v ~ /^\[[^]]*\]\([^)]*\)$/) { sub(/^\[[^]]*\]\(/, "", v); sub(/\)$/, "", v) }
    v = trim(v)

    # "*. example.com" -> "*.example.com"
    gsub(/\*\.[[:space:]]+/, "*.", v)

    prog = program_of(url)

    if (cat == "android" || cat == "ios" || cat == "apple") {
        emit(extract_app(cat, v))
        next
    }

    if (v !~ /[[:space:]]/) { emit(v); next }

    # Whitespace present: split only when every piece is a real item,
    # otherwise the value is prose and is kept verbatim.
    split_src = v
    gsub(/[[:space:]]+and[[:space:]]+/, " ", split_src)
    gsub(/[,;]+/, " ", split_src)
    gsub(/[[:space:]]+\/[[:space:]]+/, " ", split_src)
    n = split(split_src, parts, /[[:space:]]+/)
    ok = (n > 1)
    for (i = 1; i <= n; i++) if (!host_like(parts[i])) { ok = 0; break }
    if (ok) { for (i = 1; i <= n; i++) emit(parts[i]) }
    else    { emit(v) }
}

END {
    if (oos_dropped > 0)
        printf "[!] %s: dropped %d item(s) still flagged out-of-scope\n", \
            platform, oos_dropped > "/dev/stderr"
}
AWK_EOF

body="$WORKDIR/body.csv"
: > "$body"
fetched=0

# poll <platform-label> <bbscope-subcommand> [token...]
poll() {
    local label="$1" sub="$2"; shift 2
    local raw="$WORKDIR/$label.raw" errlog="$WORKDIR/$label.log" rc=0

    log "fetching $label"
    # --bbp-only: paying programs only. No --oos: in-scope items only.
    docker run --rm "$IMAGE" poll "$sub" \
        -o tcdu -d "$SEP" --bbp-only "$@" \
        >"$raw" 2>"$errlog" || rc=$?

    if [[ $rc -ne 0 ]]; then
        warn "$label: bbscope exited $rc - skipping."
        # cobra dumps its full usage on a bad flag or token; show the real error.
        if grep -Eiq '^(error|fatal)|level=(error|fatal)' "$errlog"; then
            grep -Ei '^(error|fatal)|level=(error|fatal)' "$errlog" | head -n 3 >&2
        else
            head -n 3 "$errlog" >&2 || true
        fi
        return 1
    fi

    local lines
    lines="$(wc -l < "$raw")"
    if [[ "$lines" -eq 0 ]]; then
        # bbscope exits 0 with no output when a token is rejected.
        warn "$label: returned 0 scope lines (bad/expired token, or no programs visible)"
        return 1
    fi

    awk -v platform="$label" "$NORMALIZE_AWK" "$raw" >> "$body"
    log "$label: $lines upstream lines"
    return 0
}

if [[ -n "$IT_TOKEN" ]]; then
    poll intigriti it -t "$IT_TOKEN" && fetched=$((fetched + 1)) || true
else
    warn "no Intigriti token given (-i) - skipping Intigriti"
fi

if [[ -n "$YWH_TOKEN" ]]; then
    poll yeswehack ywh -t "$YWH_TOKEN" && fetched=$((fetched + 1)) || true
else
    warn "no YesWeHack token given (-y) - skipping YesWeHack"
fi

[[ $fetched -gt 0 ]] || die "no platform returned any data; nothing written to $OUTFILE"

tmpout="$WORKDIR/out.csv"
{
    printf 'platform,program,program_url,type,category,target,raw_target,description\n'
    LC_ALL=C sort -u "$body"
} > "$tmpout"

cat -- "$tmpout" > "$OUTFILE"

rows=$(( $(wc -l < "$OUTFILE") - 1 ))
progs=$(awk -F'","' 'NR>1{print $2}' "$OUTFILE" | sort -u | wc -l)
log "wrote $rows in-scope items from $progs programs to $OUTFILE"
{
    printf '\n    items by platform/type:\n'
    awk -F'","' 'NR>1{p=$1; sub(/^"/,"",p); printf "      %-12s %s\n", p, $4}' \
        "$OUTFILE" | sort | uniq -c | sort -rn
    printf '\n'
} >&2
