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
    # shellcheck disable=SC2317  # reached when the file is executed, not sourced
    return 1 2>/dev/null || exit 1
fi
[ -n "${_SKW_ALIASES_SOURCED:-}" ] && return 0
_SKW_ALIASES_SOURCED=1

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Import Docker stuff
[[ -f "${TOOLS_DIR}/dockers/aliases.sh" ]] && source "${TOOLS_DIR}/dockers/aliases.sh"

alias mygf="${TOOLS_DIR}/misc/mygf/mygf.sh "
alias lazymap="${TOOLS_DIR}/net/lazymap/lazymap.sh "

# Jadx defaults
alias jadx='jadx -j 8 --show-bad-code --fs-case-sensitive --deobf --rename-flags all '

# Check hash information for hashcat for hash names matching $1
hashcatinfo() {
    hashcat --example-hashes | awk "/${1}/" IGNORECASE=1 RS= ORS='\n\n'
}

# Clone a website $1 into cwd
clone-website() {
    wget --mirror --convert-links --html-extension --wait=5 -o log.txt "$1"
}

# Generate list of WordPress themes (from https://twitter.com/0xLupin)
wp-wordlist-plugins() {
    curl -s https://plugins.svn.wordpress.org/ | tail -n +5 | \
        sed -e 's/<[^>]*>//g' -e 's/\///' -e 's/ \+//gp' | \
        sed -e '/^$/d' | grep -v "Powered by Apache" | \
        sort -u
}

# Generate list of WordPress themes (from https://twitter.com/0xLupin)
wp-wordlist-themes() {
    curl -s https://themes.svn.wordpress.org/ | tail -n +5 | \
        sed -e 's/<[^>]*>//g' -e 's/\///' -e 's/ \+//gp' | \
        sed -e '/^$/d' | grep -v "Powered by Apache" | \
        sort -u
}

# ???
subnets-from-hostnames() {
    nmap -iL "$1" -sL | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d . -f 1-3 | sort -u | sed 's/$/.0\/24/'
}


# Tamper with HTTP verbs on target $1, output the corresponding response codes
tamper-http-verbs() {
    local verbs="GET POST HEAD PUT DELETE CONNECT OPTIONS TRACE TRACK PATCH CUSTOM ADMIN"
    local targets="$*"
    for target in $targets; do
        echo "${target}: ";
        for verb in $verbs; \
            do echo "echo \"${verb} - $(curl -k -s -m 5 -X "${verb}" "${target}" -o /dev/null -w '%{http_code}') \""; done \
            | parallel -j 10
        echo
    done
}

# Quick lookup for file inclusions
lf-lfi() {
    gf url-lfi | qsreplace "/etc/passwd" | \
        xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
}

# Quick lookup for open redirects
lf-open-redirect() {
    local lhost="$1"
    gf url-redirect | qsreplace "$lhost" | \
        xargs -I % -P 25 sh -c "curl -Is '%' 2>&1 | grep -q 'Location: $lhost' && echo 'VULN! %'"
}

# Run sqlmap on urls provided by stdin
sqlmap-batch() {
    local ts tmp_path tmp_results results
    ts="$(date +%s)"
    tmp_path="/tmp/sqlmap_input_$ts"
    tmp_results="/tmp/sqlmap_batch_$ts"
    results="$(basename "$tmp_results")"
    sort -R > "$tmp_path"
    sqlmap -m "$tmp_path" -batch --random-agent --results-file "$tmp_results" "$@"
    cp "$tmp_results" "$results" && rm -f "$tmp_path" "$tmp_results"
}

# Filter urls to keep relevant endpoints and files
filter-urls-for-endpoints() {
    grep -v -E '\.(css|gif|ico|jpg|jpeg|pdf|png|svg|tif|ttf|txt|woff|woff2)'
}

# Search for regex $1 in all commits
search-git-commit-diff() {
    for commit in $(seq 0 "$(git reflog | wc -l)"); do
        git diff "HEAD@{$commit}" 2>/dev/null | grep -E "$1";
    done
}

# Check the IP associated with a domain and pull out the organization name
ipinfo-io() {
    dig +short "$1" | sort -Vu | while read -r line; do
        echo -n "$line "
        curl -s "https://ipinfo.io/$line" | jq -r '.org'
    done
}

# Parse base and GET parameters
parse-url() {

    show_url=1
    show_get=1
    url=""
    keep=1

    while (( keep )); do
        if [[ "$1" = "-p" ]]; then
            show_url=0
            shift
        elif [[ "$1" = "-u" ]]; then
            show_get=0
            shift
        else
            keep=0
            url="$1"
        fi
    done

    # Naively split with '?', '&', or '='
    local -a param
    IFS='?=&' read -ra param <<< "$url"

    [[ "${show_url}" = "1" ]] && echo "${param[0]}"
    if [[ "${show_get}" = "1" ]] ; then
        for i in $(seq 1 2 $(( ${#param[@]} - 1 )) ); do
            echo "${param[$i]}=${param[(($i +1))]}"
        done
    fi
}


# Run testssl.sh on targets either provided as cmd arguments or via stdin
testssl-batch() {
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
