# Some of these ideas come from:
#
# http://rez0.blog/hacking/2021/02/08/bash-aliases-command-line-tools-3.html
# https://github.com/dwisiswant0/awesome-oneliner-bugbounty
# https://blog.ropnop.com/docker-for-pentesters/
#
# Many thanks to them!

# These helpers use bash arrays and BASH_SOURCE, so refuse to run anywhere else.
# Guard against a double source too, so re-sourcing is a harmless no-op.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "aliases.sh: these helpers require bash" >&2
    return 1 2>/dev/null || exit 1
fi
[ -n "${_SKW_ALIASES_SOURCED:-}" ] && return 0
_SKW_ALIASES_SOURCED=1

_SKW_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# My tools
[[ -f "${_SKW_TOOLS_DIR}/dockers/aliases.sh" ]] && source "${_SKW_TOOLS_DIR}/dockers/aliases.sh"
[[ -f "${_SKW_TOOLS_DIR}/misc/mygf/mygf.sh" ]] && alias mygf="${_SKW_TOOLS_DIR}/misc/mygf/mygf.sh "
[[ -f "${_SKW_TOOLS_DIR}/net/lazymap/lazymap.sh" ]] && alias lazymap="${_SKW_TOOLS_DIR}/net/lazymap/lazymap.sh "

# Jadx defaults
alias jadx='jadx -j 8 --show-bad-code --fs-case-sensitive --deobf --rename-flags all '

# Check hash information for hashcat for hash names matching $1
hashcatinfo() {
    hashcat --example-hashes | awk -v IGNORECASE=1 -v RS= -v ORS='\n\n' "/${1}/"
}

# Clone a website $1 into cwd (wget log written to wget_<timestamp>.log)
clone-website() {
    wget --mirror --convert-links --html-extension --wait=5 \
        -o "wget_$(date +%s).log" "$1"
}

# Generate a sorted wordlist from a WordPress SVN index ($1 = URL)
# (from https://twitter.com/0xLupin)
wp-wordlist-from-svn() {
    curl -s "$1" | tail -n +5 | \
        sed -e 's/<[^>]*>//g' -e 's/\///' -e 's/ \+//gp' | \
        sed -e '/^$/d' | grep -v "Powered by Apache" | \
        sort -u
}

# Generate list of WordPress plugins
wp-wordlist-plugins() {
    wp-wordlist-from-svn https://plugins.svn.wordpress.org/
}

# Generate list of WordPress themes
wp-wordlist-themes() {
    wp-wordlist-from-svn https://themes.svn.wordpress.org/
}

# ???
subnets-from-hostnames() {
    nmap -iL "$1" -sL | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d . -f 1-3 | sort -u | sed 's/$/.0\/24/'
}

# Tamper with HTTP verbs on target $1, output the corresponding response codes
tamper-http-verbs() {
    local verbs=(GET POST HEAD PUT DELETE CONNECT OPTIONS TRACE TRACK PATCH CUSTOM ADMIN)
    local target
    for target in "$@"; do
        echo "${target}: "
        printf '%s\n' "${verbs[@]}" | xargs -P10 -I VERB \
            sh -c 'echo "VERB - $(curl -k -s -m5 -X VERB "$1" -o /dev/null -w "%{http_code}")"' _ "${target}"
        echo
    done
}

# Quick lookup for file inclusions
lf-lfi() {
    gf url-lfi | qsreplace "/etc/passwd" | \
        xargs -P25 -I {} sh -c 'curl -s "$1" 2>&1 | grep -q "root:x" && echo "VULN! $1"' _ {}
}

# Quick lookup for open redirects
lf-open-redirect() {
    local lhost="$1"
    gf url-redirect | qsreplace "$lhost" | \
        xargs -P25 -I {} sh -c 'curl -Is "$1" 2>&1 | grep -q "Location: $2" && echo "VULN! $1"' _ {} "$lhost"
}

# Run sqlmap on urls provided by stdin
sqlmap-batch() {
    local tmp_path tmp_results results
    tmp_path="$(mktemp)"
    tmp_results="$(mktemp)"
    trap 'rm -f "$tmp_path" "$tmp_results"' RETURN
    results="sqlmap_batch_$(date +%s)"
    sort -R > "$tmp_path"
    sqlmap -m "$tmp_path" -batch --random-agent --results-file "$tmp_results" "$@"
    cp "$tmp_results" "$results"
}

# Filter urls to keep relevant endpoints and files
filter-urls-for-endpoints() {
    grep -v -E '\.(css|gif|ico|jpg|jpeg|pdf|png|svg|tif|ttf|txt|woff|woff2)'
}

# Search for regex $1 across the diffs of every commit on all branches
search-git-commit-diff() {
    git log --all -p -G"$1"
}

# Check the IP associated with a domain and pull out the organization name
ipinfo-io() {
    dig +short "$1" | sort -Vu | while read -r line; do
        echo -n "$line "
        curl -s "https://ipinfo.io/$line" | jq -r '.org'
    done
}

# Parse base and GET parameters
# -p: print GET params only (hide base URL); -u: print base URL only (hide params)
parse-url() {
    local show_url=1 show_get=1 url opt i OPTIND=1
    local -a param

    while getopts "pu" opt; do
        case "$opt" in
            p) show_url=0 ;;
            u) show_get=0 ;;
            *) return 1 ;;
        esac
    done
    shift $(( OPTIND - 1 ))
    url="$1"

    # Naively split with '?', '&', or '='
    IFS='?=&' read -ra param <<< "$url"

    [[ "$show_url" = 1 ]] && echo "${param[0]}"
    if [[ "$show_get" = 1 ]]; then
        for (( i = 1; i < ${#param[@]}; i += 2 )); do
            echo "${param[i]}=${param[i+1]}"
        done
    fi
}


# Run testssl.sh on targets either provided as cmd arguments or via stdin
testssl-batch() {
    local line target port
    while read -r line
    do
        # Parse target and port number (if existing)
        target=$(sed 's/https\?:\/\///' <<< "$line")
        port=$(grep -Eo ":([[:digit:]]+)" <<< "$target" | cut -d':' -f2) #dirty
        if [ -z "$port" ]; then
            target="${target}:443"
        fi

        timeout 10m testssl --connect-timeout 60 --openssl-timeout 60 \
                --warnings off \
                --sneaky --bugs \
                --hints --append -oA "testssl_${target/:/_}" "${target}"

        sleep 20
    done < "${1:-/dev/stdin}"
}
