#!/usr/bin/env bash
#
# fetch-external-tools.sh
#
# Fetch a curated set of external offensive-security tools and drop them into
# this repository, ready to be copied onto a target and run "as is".
#
# Strategy, per tool, in order of preference:
#   1. a pre-compiled binary (from a GitHub release or a binary-only repo);
#   2. otherwise the raw script / latest release artefact;
#   3. as a last resort, a shallow clone with its ".git/" directory removed.
#
# The choice made for each tool is documented in its function below and in
# README.org.
#
# Usage:
#   ./fetch-external-tools.sh                 # fetch everything
#   ./fetch-external-tools.sh chisel ligolo   # fetch only the named tools
#   ./fetch-external-tools.sh --list          # list available tool names
#   ./fetch-external-tools.sh --force all      # re-fetch even if present
#
# Environment:
#   GITHUB_TOKEN   optional; raises the GitHub API rate limit if set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
FORCE=0

# All fetchable tools, in the order they should run.
ALL_TOOLS=(
    1337dict
    sysinternals
    chisel
    ligolo
    netcat
    socat
    static-binaries
    powercat
    linpeas
    lse
    les
    pspy
    deepce
    pwnkit
    empire
    mimikatz
    powersploit
    rubeus
    watson
    wes
    winpeas
    privesccheck
    printspoofer
    lazagne
    sharphound
    inveigh
    ghostpack-compiled
    hermes-decomp
    apkleaks
    trufflehog
)

# Log helpers
if [[ -t 1 ]]; then
    C_RST=$'\e[0m'; C_BLU=$'\e[1;34m'; C_GRN=$'\e[1;32m'; C_YLW=$'\e[1;33m'; C_RED=$'\e[1;31m'
else
    C_RST=; C_BLU=; C_GRN=; C_YLW=; C_RED=
fi

msg()  { printf '%s[*]%s %s\n'  "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[+]%s %s\n'  "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n'  "$C_YLW" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n'  "$C_RED" "$C_RST" "$*" >&2; }

# Abort if a required command is missing
need() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || { err "missing required command: $c"; exit 1; }
    done
}

# curl wrapper: fail on HTTP errors, follow redirects, quiet, retry.
dl() {
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$@"
}

# curl wrapper for the GitHub API, adding auth if GITHUB_TOKEN is set.
gh_api() {
    local url="$1"
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        dl -H "Authorization: Bearer ${GITHUB_TOKEN}" \
           -H "Accept: application/vnd.github+json" "$url"
    else
        dl -H "Accept: application/vnd.github+json" "$url"
    fi
}

# Print the browser_download_url of the first asset in a repo's latest release
# whose name matches the given (extended) regex. Empty output means "not found"
# (which includes the GitHub API rate limit being hit -- see warn below).
#   $1 = owner/repo   $2 = asset name regex
gh_latest_asset() {
    local json
    if ! json="$(gh_api "https://api.github.com/repos/$1/releases/latest" 2>/dev/null)"; then
        warn "GitHub API request for $1 failed (rate limit? set GITHUB_TOKEN to raise it)"
        return 1
    fi
    if grep -q '"message".*rate limit' <<<"$json"; then
        warn "GitHub API rate limit hit for $1 (set GITHUB_TOKEN to raise it)"
        return 1
    fi
    jq -r --arg re "$2" \
        '.assets[]? | select(.name | test($re)) | .browser_download_url' \
        <<<"$json" | head -n1
}

# Prepare a tool directory. Returns non-zero (and the caller returns) when the
# directory already has content and --force was not given.
prepare_dir() {
    local dir="$1"
    if [[ -e "$dir" && -n "$(ls -A "$dir" 2>/dev/null)" && "$FORCE" -ne 1 ]]; then
        warn "$(basename "$dir") already present, skipping (use --force to refresh)"
        return 1
    fi
    rm -rf "$dir"
    mkdir -p "$dir"
    return 0
}

# Shallow-clone a repo then strip its .git directory: gives a plain source tree.
#   $1 = clone url   $2 = branch   $3 = destination dir
clone_stripped() {
    local url="$1" branch="$2" dest="$3"
    msg "cloning $url ($branch) and removing .git/"
    git clone --depth 1 --branch "$branch" --quiet "$url" "$dest"
    rm -rf "$dest/.git"
}

# Per-tool fetchers

# 1337dict -- a single self-contained Python wordlist generator.
# Best option: fetch the raw script (runs as-is, no build, no clone).
fetch_1337dict() {
    local dir="$SCRIPT_DIR/misc/1337dict"
    prepare_dir "$dir" || return 0
    dl -o "$dir/1337dict.py" \
        "https://raw.githubusercontent.com/cym13/1337dict/master/1337dict.py"
    chmod +x "$dir/1337dict.py"
    ok "1337dict -> misc/1337dict/1337dict.py"
}

# Sysinternals -- Microsoft's suite of signed Windows utilities (procdump,
# accesschk, PsExec, autoruns, ...). Distributed by Microsoft, not GitHub.
# Best option: download the official suite zip and extract it. NB: large
# (~190 MB) and pulled straight from download.sysinternals.com.
fetch_sysinternals() {
    local dir="$SCRIPT_DIR/misc/sysinternals"
    prepare_dir "$dir" || return 0
    local tmp
    tmp="$(mktemp -d)"
    dl -o "$tmp/SysinternalsSuite.zip" \
        "https://download.sysinternals.com/files/SysinternalsSuite.zip"
    unzip -o -q "$tmp/SysinternalsSuite.zip" -d "$dir"
    rm -rf "$tmp"
    ok "sysinternals -> misc/sysinternals/ (signed MS utilities, ~190 MB)"
}

# chisel -- fast TCP/UDP tunnel. Ships pre-compiled binaries per platform.
# Best option: pre-compiled binaries (linux/amd64 gzip, windows/amd64 zip).
fetch_chisel() {
    local dir="$SCRIPT_DIR/net/chisel"
    prepare_dir "$dir" || return 0
    local url tmp
    tmp="$(mktemp -d)"

    url="$(gh_latest_asset jpillora/chisel 'linux_amd64\.gz$')"
    if [[ -n "$url" ]]; then
        dl -o "$tmp/chisel.gz" "$url"
        gzip -dc "$tmp/chisel.gz" > "$dir/chisel"
        chmod +x "$dir/chisel"
        ok "chisel (linux/amd64) -> net/chisel/chisel"
    else
        warn "chisel: no linux/amd64 asset found"
    fi

    url="$(gh_latest_asset jpillora/chisel 'windows_amd64\.zip$')"
    if [[ -n "$url" ]]; then
        dl -o "$tmp/chisel.zip" "$url"
        unzip -o -q "$tmp/chisel.zip" -d "$tmp/chisel-win"
        cp "$tmp"/chisel-win/chisel*.exe "$dir/chisel.exe" 2>/dev/null \
            || cp "$(find "$tmp/chisel-win" -name '*.exe' | head -n1)" "$dir/chisel.exe"
        ok "chisel (windows/amd64) -> net/chisel/chisel.exe"
    else
        warn "chisel: no windows/amd64 asset found"
    fi
    rm -rf "$tmp"
}

# ligolo-ng -- reverse tunneling with a tun interface. Ships pre-compiled
# "agent" (drop on target) and "proxy" (run on attacker) binaries.
# Best option: pre-compiled binaries (linux + windows agent, linux proxy).
fetch_ligolo() {
    local dir="$SCRIPT_DIR/net/ligolo"
    prepare_dir "$dir" || return 0
    local tmp url
    tmp="$(mktemp -d)"

    _ligolo_grab() { # $1=asset-regex $2=member-in-archive $3=output-name
        url="$(gh_latest_asset nicocha30/ligolo-ng "$1")"
        [[ -n "$url" ]] || { warn "ligolo: no asset matching /$1/"; return; }
        local f="$tmp/dl"
        case "$url" in
            *.zip)    dl -o "$f.zip" "$url"; unzip -o -q "$f.zip" -d "$tmp/ex" ;;
            *.tar.gz) dl -o "$f.tgz" "$url"; mkdir -p "$tmp/ex"; tar -xzf "$f.tgz" -C "$tmp/ex" ;;
        esac
        cp "$(find "$tmp/ex" -name "$2" | head -n1)" "$dir/$3"
        chmod +x "$dir/$3" 2>/dev/null || true
        rm -rf "$tmp/ex" "$f".*
        ok "ligolo -> net/ligolo/$3"
    }

    _ligolo_grab 'agent_.*_linux_amd64\.tar\.gz$'   'agent'      'ligolo-agent'
    _ligolo_grab 'agent_.*_windows_amd64\.zip$'     'agent.exe'  'ligolo-agent.exe'
    _ligolo_grab 'proxy_.*_linux_amd64\.tar\.gz$'   'proxy'      'ligolo-proxy'
    unset -f _ligolo_grab
    rm -rf "$tmp"
}

# netcat -- two sources requested:
#   * H74N/netcat-binaries : a ready-to-run static Linux "nc" binary  -> best.
#   * diegocr/netcat       : portable C source (build for other targets).
# Best option: the pre-compiled binary, plus the source tree alongside it.
fetch_netcat() {
    local dir="$SCRIPT_DIR/net/netcat"
    prepare_dir "$dir" || return 0
    dl -o "$dir/nc" \
        "https://raw.githubusercontent.com/H74N/netcat-binaries/master/nc"
    chmod +x "$dir/nc"
    ok "netcat (static binary) -> net/netcat/nc"
    clone_stripped "https://github.com/diegocr/netcat.git" master "$dir/src"
    ok "netcat (source) -> net/netcat/src/"
}

# socat -- lilydjwg's socat2 fork. No releases and no pre-compiled binary are
# published, so it must be built from source (Config/ has static makefiles).
# Best option: clone the source and strip .git.
fetch_socat() {
    local dir="$SCRIPT_DIR/net/socat"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/lilydjwg/socat.git" socat2 "$dir"
    ok "socat (source) -> net/socat/ (build with: autoconf && ./configure && make)"
}

# static-binaries -- andrew-d's collection of statically-linked binaries
# (nc, socat, ncat, nmap, python, bash, gdb, ...) for pushing onto minimal or
# odd-arch targets. Binaries live in the repo; there is no release.
# Best option: clone the source and strip .git. NB: large (~65 MB).
fetch_static_binaries() {
    local dir="$SCRIPT_DIR/net/static-binaries"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/andrew-d/static-binaries.git" master "$dir"
    ok "static-binaries -> net/static-binaries/ (pre-built static tools, ~65 MB)"
}

# powercat -- netcat implemented in PowerShell, a single self-contained script.
# Windows-native companion to net/netcat.
# Best option: fetch the raw powercat.ps1 (runs as-is).
fetch_powercat() {
    local dir="$SCRIPT_DIR/net/powercat"
    prepare_dir "$dir" || return 0
    dl -o "$dir/powercat.ps1" \
        "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1"
    ok "powercat -> net/powercat/powercat.ps1"
}

# linPEAS -- Linux privesc enumeration. PEASS-ng publishes the built script
# and native binaries as release assets.
# Best option: the ready-to-run linpeas.sh (plus the linux/amd64 binary).
fetch_linpeas() {
    local dir="$SCRIPT_DIR/privesc/unix/linpeas"
    prepare_dir "$dir" || return 0
    local url
    url="$(gh_latest_asset peass-ng/PEASS-ng '^linpeas\.sh$')"
    if [[ -z "$url" ]]; then err "linpeas: could not resolve linpeas.sh release asset"; return 1; fi
    dl -o "$dir/linpeas.sh" "$url"
    chmod +x "$dir/linpeas.sh"
    ok "linpeas -> privesc/unix/linpeas/linpeas.sh"
    url="$(gh_latest_asset peass-ng/PEASS-ng '^linpeas_linux_amd64$')"
    if [[ -n "$url" ]]; then
        dl -o "$dir/linpeas_linux_amd64" "$url"
        chmod +x "$dir/linpeas_linux_amd64"
        ok "linpeas (binary) -> privesc/unix/linpeas/linpeas_linux_amd64"
    fi
}

# lse -- Linux Smart Enumeration, a single self-contained shell script.
# Best option: fetch the raw lse.sh (runs as-is).
fetch_lse() {
    local dir="$SCRIPT_DIR/privesc/unix/lse"
    prepare_dir "$dir" || return 0
    dl -o "$dir/lse.sh" \
        "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh"
    chmod +x "$dir/lse.sh"
    ok "lse -> privesc/unix/lse/lse.sh"
}

# les -- Linux Exploit Suggester, a single self-contained shell script that
# maps the kernel/userland to known local exploits. Complements lse/linpeas.
# Best option: fetch the raw script (runs as-is).
fetch_les() {
    local dir="$SCRIPT_DIR/privesc/unix/les"
    prepare_dir "$dir" || return 0
    dl -o "$dir/les.sh" \
        "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh"
    chmod +x "$dir/les.sh"
    ok "les -> privesc/unix/les/les.sh"
}

# pspy -- watch processes / cron without root. Ships static release binaries.
# Best option: pre-compiled binaries (linux amd64 + 386, statically linked).
fetch_pspy() {
    local dir="$SCRIPT_DIR/privesc/unix/pspy"
    prepare_dir "$dir" || return 0
    local url
    url="$(gh_latest_asset DominicBreuker/pspy '^pspy64$')"
    if [[ -z "$url" ]]; then err "pspy: could not resolve pspy64 release asset"; return 1; fi
    dl -o "$dir/pspy64" "$url"; chmod +x "$dir/pspy64"
    ok "pspy (linux/amd64) -> privesc/unix/pspy/pspy64"
    url="$(gh_latest_asset DominicBreuker/pspy '^pspy32$')"
    if [[ -n "$url" ]]; then
        dl -o "$dir/pspy32" "$url"; chmod +x "$dir/pspy32"
        ok "pspy (linux/386) -> privesc/unix/pspy/pspy32"
    fi
}

# deepce -- Docker / container enumeration and escape helper, a single
# self-contained shell script.
# Best option: fetch the raw script (runs as-is).
fetch_deepce() {
    local dir="$SCRIPT_DIR/privesc/unix/deepce"
    prepare_dir "$dir" || return 0
    dl -o "$dir/deepce.sh" \
        "https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh"
    chmod +x "$dir/deepce.sh"
    ok "deepce -> privesc/unix/deepce/deepce.sh"
}

# PwnKit -- CVE-2021-4034 (pkexec) local privesc PoC. C source + build script,
# no pre-compiled binary published.
# Best option: clone the source and strip .git (build with make).
fetch_pwnkit() {
    local dir="$SCRIPT_DIR/privesc/unix/pwnkit"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/luijait/PwnKit-Exploit.git" main "$dir"
    ok "pwnkit (source) -> privesc/unix/pwnkit/ (build with: make)"
}

# Empire -- large post-exploitation framework (Python). No standalone binary;
# used from its source tree.
# Best option: clone the source and strip .git.
fetch_empire() {
    local dir="$SCRIPT_DIR/privesc/win/empire"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/EmpireProject/Empire.git" master "$dir"
    ok "empire (source) -> privesc/win/empire/"
}

# mimikatz -- Windows credential tooling. Ships a pre-compiled release archive.
# Best option: the pre-compiled mimikatz_trunk.zip (extracted in place).
fetch_mimikatz() {
    local dir="$SCRIPT_DIR/privesc/win/mimikatz"
    prepare_dir "$dir" || return 0
    local url tmp
    tmp="$(mktemp -d)"
    url="$(gh_latest_asset gentilkiwi/mimikatz '^mimikatz_trunk\.zip$')"
    if [[ -z "$url" ]]; then
        err "mimikatz: could not resolve mimikatz_trunk.zip release asset"
        rm -rf "$tmp"; return 1
    fi
    dl -o "$tmp/mimikatz.zip" "$url"
    unzip -o -q "$tmp/mimikatz.zip" -d "$dir"
    rm -rf "$tmp"
    ok "mimikatz (binaries) -> privesc/win/mimikatz/ (x64/, Win32/)"
}

# PowerSploit -- collection of PowerShell offensive modules, run as-is.
# No binary/release; used directly from the .ps1 files.
# Best option: clone the source and strip .git.
fetch_powersploit() {
    local dir="$SCRIPT_DIR/privesc/win/powersploit"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/PowerShellMafia/PowerSploit.git" master "$dir"
    ok "powersploit (scripts) -> privesc/win/powersploit/"
}

# Rubeus -- C# Kerberos abuse toolkit. No pre-compiled release (must be built
# in Visual Studio / with the .NET SDK).
# Best option: clone the source and strip .git.
fetch_rubeus() {
    local dir="$SCRIPT_DIR/privesc/win/rubeus"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/GhostPack/Rubeus.git" master "$dir"
    ok "rubeus (source) -> privesc/win/rubeus/ (build with the .NET SDK)"
}

# Watson -- C# .NET missing-patch enumeration. No pre-compiled release.
# Best option: clone the source and strip .git.
fetch_watson() {
    local dir="$SCRIPT_DIR/privesc/win/watson"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/rasta-mouse/Watson.git" master "$dir"
    ok "watson (source) -> privesc/win/watson/ (build with the .NET SDK)"
}

# WES-NG -- Windows Exploit Suggester, a single self-contained Python script.
# Best option: fetch the raw wes.py (runs as-is; refresh its DB with --update).
fetch_wes() {
    local dir="$SCRIPT_DIR/privesc/win/wes"
    prepare_dir "$dir" || return 0
    dl -o "$dir/wes.py" \
        "https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py"
    chmod +x "$dir/wes.py"
    ok "wes -> privesc/win/wes/wes.py (run 'python wes.py --update' to fetch the DB)"
}

# winPEAS -- Windows privesc enumeration. PEASS-ng publishes ready-to-run
# executables and a .bat as release assets.
# Best option: the pre-compiled winPEASx64.exe / winPEASany.exe (+ the .bat).
fetch_winpeas() {
    local dir="$SCRIPT_DIR/privesc/win/winpeas"
    prepare_dir "$dir" || return 0
    local url got=0
    for pair in \
        'winPEASx64\.exe$|winPEASx64.exe' \
        'winPEASany\.exe$|winPEASany.exe' \
        'winPEAS\.bat$|winPEAS.bat'; do
        url="$(gh_latest_asset peass-ng/PEASS-ng "^${pair%%|*}")" || true
        if [[ -n "$url" ]]; then
            dl -o "$dir/${pair##*|}" "$url"
            ok "winpeas -> privesc/win/winpeas/${pair##*|}"
            got=1
        fi
    done
    if [[ "$got" -ne 1 ]]; then err "winpeas: could not resolve any winPEAS release asset"; return 1; fi
}

# PrivescCheck -- self-contained PowerShell Windows privesc enumerator, lighter
# and stealthier than winPEAS. Ships the built PrivescCheck.ps1 as a release
# asset (it is assembled from src/ at release time).
# Best option: the ready-to-run PrivescCheck.ps1 release script.
fetch_privesccheck() {
    local dir="$SCRIPT_DIR/privesc/win/privesccheck"
    prepare_dir "$dir" || return 0
    local url
    url="$(gh_latest_asset itm4n/PrivescCheck '^PrivescCheck\.ps1$')"
    if [[ -z "$url" ]]; then err "privesccheck: could not resolve PrivescCheck.ps1 release asset"; return 1; fi
    dl -o "$dir/PrivescCheck.ps1" "$url"
    ok "privesccheck -> privesc/win/privesccheck/PrivescCheck.ps1"
}

# PrintSpoofer -- SeImpersonate/SeAssignPrimaryToken local privesc. Ships
# pre-compiled release executables (x64 + x86). Expect AV detection.
# Best option: pre-compiled binaries.
fetch_printspoofer() {
    local dir="$SCRIPT_DIR/privesc/win/printspoofer"
    prepare_dir "$dir" || return 0
    local url
    url="$(gh_latest_asset itm4n/PrintSpoofer '^PrintSpoofer64\.exe$')"
    if [[ -z "$url" ]]; then err "printspoofer: could not resolve PrintSpoofer64.exe"; return 1; fi
    dl -o "$dir/PrintSpoofer64.exe" "$url"
    ok "printspoofer (x64) -> privesc/win/printspoofer/PrintSpoofer64.exe"
    url="$(gh_latest_asset itm4n/PrintSpoofer '^PrintSpoofer32\.exe$')"
    if [[ -n "$url" ]]; then
        dl -o "$dir/PrintSpoofer32.exe" "$url"
        ok "printspoofer (x86) -> privesc/win/printspoofer/PrintSpoofer32.exe"
    fi
}

# LaZagne -- local credential recovery for many apps. Ships a pre-compiled
# release executable. Expect AV detection.
# Best option: the pre-compiled LaZagne.exe.
fetch_lazagne() {
    local dir="$SCRIPT_DIR/privesc/win/lazagne"
    prepare_dir "$dir" || return 0
    local url
    url="$(gh_latest_asset AlessandroZ/LaZagne '^LaZagne\.exe$')"
    if [[ -z "$url" ]]; then err "lazagne: could not resolve LaZagne.exe release asset"; return 1; fi
    dl -o "$dir/LaZagne.exe" "$url"
    ok "lazagne -> privesc/win/lazagne/LaZagne.exe"
}

# SharpHound -- BloodHound AD collector. Ships a pre-compiled release zip
# (the collector .exe + dependencies). We take the non-debug windows build.
# Best option: pre-compiled binary (extracted from the release zip).
fetch_sharphound() {
    local dir="$SCRIPT_DIR/privesc/win/sharphound"
    prepare_dir "$dir" || return 0
    local url tmp
    tmp="$(mktemp -d)"
    # Match e.g. SharpHound_v2.14.0_windows_x86.zip, excluding the +debug build.
    url="$(gh_latest_asset SpecterOps/SharpHound '^SharpHound_v[0-9.]+_windows_x86\.zip$')"
    if [[ -z "$url" ]]; then
        err "sharphound: could not resolve SharpHound release zip"; rm -rf "$tmp"; return 1
    fi
    dl -o "$tmp/sharphound.zip" "$url"
    unzip -o -q "$tmp/sharphound.zip" -d "$dir"
    rm -rf "$tmp"
    ok "sharphound -> privesc/win/sharphound/"
}

# Inveigh -- LLMNR/NBNS/mDNS spoofer and man-in-the-middle. Ships pre-compiled
# release builds; we take the self-contained win-x64 single-file build.
# Best option: pre-compiled binary (extracted from the release zip).
fetch_inveigh() {
    local dir="$SCRIPT_DIR/privesc/win/inveigh"
    prepare_dir "$dir" || return 0
    local url tmp
    tmp="$(mktemp -d)"
    url="$(gh_latest_asset Kevin-Robertson/Inveigh 'win-x64-trimmed-single.*\.zip$')"
    if [[ -z "$url" ]]; then
        err "inveigh: could not resolve win-x64 release zip"; rm -rf "$tmp"; return 1
    fi
    dl -o "$tmp/inveigh.zip" "$url"
    unzip -o -q "$tmp/inveigh.zip" -d "$dir"
    rm -rf "$tmp"
    ok "inveigh (win/x64) -> privesc/win/inveigh/"
}

# Ghostpack-CompiledBinaries -- ready-to-run builds of Rubeus, Seatbelt,
# SharpUp, Certify, etc. Removes the need to build the GhostPack C# tools.
# Best option: clone the repo (binaries live in it) and strip .git.
fetch_ghostpack_compiled() {
    local dir="$SCRIPT_DIR/privesc/win/ghostpack-compiled"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git" master "$dir"
    ok "ghostpack-compiled -> privesc/win/ghostpack-compiled/ (pre-built Rubeus, Seatbelt, ...)"
}

# hermes-decomp -- decompiler for React Native Hermes bytecode (.hbc). Ships
# pre-compiled release archives per platform; the linux/x86_64 tarball holds
# the "hermes-decomp" CLI plus the "hermes-mcp" server binary.
# Best option: the pre-compiled linux/x86_64 binaries (extracted in place).
fetch_hermes_decomp() {
    local dir="$SCRIPT_DIR/android/hermes-decomp"
    prepare_dir "$dir" || return 0
    local url tmp
    tmp="$(mktemp -d)"
    url="$(gh_latest_asset SymbioticSec/hermes-decomp 'linux-x86_64\.tar\.gz$')"
    if [[ -z "$url" ]]; then
        err "hermes-decomp: could not resolve linux/x86_64 release tarball"; rm -rf "$tmp"; return 1
    fi
    dl -o "$tmp/hermes-decomp.tar.gz" "$url"
    tar -xzf "$tmp/hermes-decomp.tar.gz" -C "$dir"
    chmod +x "$dir"/hermes-decomp "$dir"/hermes-mcp 2>/dev/null || true
    rm -rf "$tmp"
    ok "hermes-decomp (linux/x86_64) -> android/hermes-decomp/ (hermes-decomp, hermes-mcp)"
}

# apkleaks -- scans an APK for URLs, endpoints and secrets. Python tool with no
# pre-compiled release; it also shells out to jadx to decompile the APK first.
# Best option: clone the source and strip .git (needs Python 3 + jadx in PATH).
fetch_apkleaks() {
    local dir="$SCRIPT_DIR/android/apkleaks"
    prepare_dir "$dir" || return 0
    clone_stripped "https://github.com/dwisiswant0/apkleaks.git" master "$dir"
    ok "apkleaks (source) -> android/apkleaks/ (pip install -r requirements.txt; needs jadx in PATH)"
}

# trufflehog -- fast secret scanner with verification; run it over a decoded APK
# tree (e.g. 'trufflehog filesystem <dir>') to surface live credentials. Ships
# pre-compiled release binaries per platform.
# Best option: the pre-compiled linux/amd64 binary (extracted from the tarball).
fetch_trufflehog() {
    local dir="$SCRIPT_DIR/android/trufflehog"
    prepare_dir "$dir" || return 0
    local url tmp
    tmp="$(mktemp -d)"
    url="$(gh_latest_asset trufflesecurity/trufflehog 'linux_amd64\.tar\.gz$')"
    if [[ -z "$url" ]]; then
        err "trufflehog: could not resolve linux/amd64 release tarball"; rm -rf "$tmp"; return 1
    fi
    dl -o "$tmp/trufflehog.tar.gz" "$url"
    tar -xzf "$tmp/trufflehog.tar.gz" -C "$tmp" trufflehog
    cp "$tmp/trufflehog" "$dir/trufflehog"
    chmod +x "$dir/trufflehog"
    rm -rf "$tmp"
    ok "trufflehog (linux/amd64) -> android/trufflehog/trufflehog"
}

# Dispatch

run_tool() {
    local t="$1"
    case "$t" in
        1337dict)    fetch_1337dict ;;
        sysinternals)      fetch_sysinternals ;;
        chisel)      fetch_chisel ;;
        ligolo)      fetch_ligolo ;;
        netcat)      fetch_netcat ;;
        socat)       fetch_socat ;;
        static-binaries)   fetch_static_binaries ;;
        powercat)    fetch_powercat ;;
        linpeas)     fetch_linpeas ;;
        lse)         fetch_lse ;;
        les)         fetch_les ;;
        pspy)        fetch_pspy ;;
        deepce)      fetch_deepce ;;
        pwnkit)      fetch_pwnkit ;;
        empire)      fetch_empire ;;
        mimikatz)    fetch_mimikatz ;;
        powersploit) fetch_powersploit ;;
        rubeus)      fetch_rubeus ;;
        watson)      fetch_watson ;;
        wes)         fetch_wes ;;
        winpeas)     fetch_winpeas ;;
        privesccheck)      fetch_privesccheck ;;
        printspoofer)      fetch_printspoofer ;;
        lazagne)     fetch_lazagne ;;
        sharphound)  fetch_sharphound ;;
        inveigh)     fetch_inveigh ;;
        ghostpack-compiled)   fetch_ghostpack_compiled ;;
        hermes-decomp)     fetch_hermes_decomp ;;
        apkleaks)    fetch_apkleaks ;;
        trufflehog)  fetch_trufflehog ;;
        *)           err "unknown tool: $t"; return 1 ;;
    esac
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [--force] [--list] [tool ...]

With no tool names (or "all"), fetches every tool. Available tools:
  ${ALL_TOOLS[*]}

Options:
  --force   re-fetch tools even if their directory already exists
  --list    print the available tool names and exit
  -h,--help show this help
EOF
}

main() {
    need curl jq git tar gzip unzip

    local -a wanted=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)    FORCE=1 ;;
            --list)     printf '%s\n' "${ALL_TOOLS[@]}"; exit 0 ;;
            -h|--help)  usage; exit 0 ;;
            all)        wanted=("${ALL_TOOLS[@]}") ;;
            -*)         err "unknown option: $1"; usage; exit 1 ;;
            *)          wanted+=("$1") ;;
        esac
        shift
    done
    [[ ${#wanted[@]} -eq 0 ]] && wanted=("${ALL_TOOLS[@]}")

    local t rc=0
    for t in "${wanted[@]}"; do
        printf '\n'
        msg "=== ${t} ==="
        if ! run_tool "$t"; then
            rc=1
            err "${t}: failed"
        fi
    done

    printf '\n'
    if [[ $rc -eq 0 ]]; then
        ok "done."
    else
        warn "done, with errors (see above)."
    fi
    return $rc
}

main "$@"
