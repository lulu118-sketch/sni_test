#!/usr/bin/env bash
# ============================================================
# Reality SNI Tester v2.5.2 Professional
# ============================================================
#
# Authorized SNI / TLS connectivity & stability tester.
#
# Pipeline:
#
#   SNI candidates
#        |
#   De-duplication
#        |
#   Fast screening
#        |
#   TOP12
#        |
#   Precision 100 rounds
#        |
#   P50 / P75 / P90 / P95 / P99
#        |
#   Jitter
#        |
#   Risk Penalty
#        |
#   Stability Score
#        |
#   PASS / WARN / FAIL
#        |
#   Final ranking
#        |
#   PRIMARY / BACKUP / BACKUP2
#
# Requirements:
#   Bash 4+
#   OpenSSL
#   timeout
#   awk
#   sort
#   sed
#   grep
#   xargs
#   ip
#
# This script measures TLS/SNI connectivity and stability.
# It does not attempt to bypass security controls.
#
# ============================================================

set -u
set -o pipefail

VERSION="2.5.2 Professional"

# ============================================================
# 1. Configuration
# ============================================================

# ------------------------------------------------------------
# Network mode
#
# FORCE_IPV4=1 -> IPv4 only
# FORCE_IPV6=1 -> IPv6 only
# both 0       -> AUTO
#
# If FORCE_IPV4=1 but IPv4 is unavailable,
# the script automatically falls back to AUTO.
# ------------------------------------------------------------

FORCE_IPV4=1
FORCE_IPV6=0

# ------------------------------------------------------------
# Fast screening
# ------------------------------------------------------------

FAST_ROUNDS=6
FAST_CONC=6
FAST_TIMEOUT=3

# ------------------------------------------------------------
# Precision testing
# ------------------------------------------------------------

PRECISION_TOP=12
PRECISION_ROUNDS=100
PRECISION_CONC=3
PRECISION_TIMEOUT=5

# ------------------------------------------------------------
# Pause
#
# Precision uses a modest delay between rounds.
# This is intended to reduce measurement noise and avoid
# unnecessary load on authorized test targets.
# ------------------------------------------------------------

ROUND_PAUSE_MIN=1
ROUND_PAUSE_MAX=3

BATCH_SIZE=10
BATCH_PAUSE_MIN=3
BATCH_PAUSE_MAX=8

# ------------------------------------------------------------
# Fast screening minimum
# ------------------------------------------------------------

FAST_MIN_SUCCESS=50

# ------------------------------------------------------------
# PASS thresholds
# ------------------------------------------------------------

PASS_SUCCESS=99
PASS_P95=700
PASS_P99=1500
PASS_RISK=5

# ------------------------------------------------------------
# WARN thresholds
# ------------------------------------------------------------

WARN_SUCCESS=97
WARN_P95=1000
WARN_P99=2000
WARN_RISK=10

# ============================================================
# 2. SNI candidates
# ============================================================

SNI_LIST=(
    "a0.awsstatic.com"
    "lpcdn.lpsnmedia.net"
    "j.6sc.co"
    "xp.apple.com"
    "s.go-mpulse.net"
    "www.nvidia.com"
    "statici.icloud.com"
    "sisu.xboxlive.com"
    "www.wowt.com"
    "fpinit.itunes.apple.com"
    "c.s-microsoft.com"
    "www.icloud.com"
    "r.bing.com"
    "cdn.userway.org"
    "ts2.tc.mm.bing.net"
    "azure.microsoft.com"
    "amp-api-edge.apps.apple.com"
    "www.xilinx.com"
    "apps.mzstatic.com"
    "devblogs.microsoft.com"
    "snap.licdn.com"
    "s0.awsstatic.com"
    "ipv6.6sc.co"
    "th.bing.com"
    "ts4.tc.mm.bing.net"
    "drivers.amd.com"
    "go.microsoft.com"
    "amd.com"
    "s.mp.marsflag.com"
    "d2c.aws.amazon.com"
    "ts1.tc.mm.bing.net"
    "t0.m.awsstatic.com"
    "digitalassets.tesla.com"
    "www.oracle.com"
    "downloadmirror.intel.com"
    "iosapps.itunes.apple.com"
    "cua-chat-ui.tesla.com"
    "mscom.demdex.net"
    "www.xbox.com"
    "i7158c100-ds-aksb-a.akamaihd.net"
    "intelcorp.scene7.com"
    "www.amd.com"
    "gray.video-player.arcpublishing.com"
    "c.6sc.co"
    "ts3.tc.mm.bing.net"
    "ce.mf.marsflag.com"
    "www.tesla.com"
    "www.apple.com"
    "www.microsoft.com"
    "apps.apple.com"
    "www.cartoonbrew.com"
    "shin-ei-animation.jp"
    "www.ritao.co"
    "ani-com.hk"
    "d1.awsstatic.com"
    "displaycatalog.mp.microsoft.com"
    "cdn-dynmedia-1.microsoft.com"
    "res-1.cdn.office.net"
    "se-edge.itunes.apple.com"
    "swcdn.apple.com"
    "downloaddispatch.itunes.apple.com"
    "download.amd.com"
    "images.nvidia.com"
    "store-images.s-microsoft.com"
)

# ============================================================
# 3. Environment validation
# ============================================================

if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "ERROR: This script requires Bash." >&2
    exit 1
fi

if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: Bash 4.0+ is required." >&2
    echo "Current version: $BASH_VERSION" >&2
    exit 1
fi

if [[ "$FORCE_IPV4" -eq 1 && "$FORCE_IPV6" -eq 1 ]]; then
    echo "ERROR: FORCE_IPV4 and FORCE_IPV6 cannot both be 1." >&2
    exit 1
fi

# ============================================================
# 4. Dependency check
# ============================================================

REQUIRED_COMMANDS=(
    openssl
    timeout
    awk
    sort
    sed
    grep
    xargs
    ip
    date
    wc
    head
    cut
    nl
)

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Missing command: $cmd" >&2
        echo >&2
        echo "Debian / Ubuntu:" >&2
        echo "  apt update" >&2
        echo "  apt install -y openssl coreutils gawk sed grep findutils iproute2" >&2
        exit 1
    fi
done

# ============================================================
# 5. Network detection
# ============================================================

check_ipv4() {
    if ! ip -4 route show default 2>/dev/null |
        grep -q '^default'
    then
        return 1
    fi

    if ! timeout 4 bash -c \
        'exec 3<>/dev/tcp/1.1.1.1/443' \
        >/dev/null 2>&1
    then
        return 1
    fi

    return 0
}

check_ipv6() {
    if ! ip -6 route show default 2>/dev/null |
        grep -q '^default'
    then
        return 1
    fi

    return 0
}

NETWORK_MODE=""

if [[ "$FORCE_IPV4" -eq 1 ]]; then

    echo "[Network] Checking IPv4..."

    if check_ipv4; then
        NETWORK_MODE="IPv4"
    else
        echo "WARNING: IPv4 unavailable."
        echo "Falling back to AUTO."
        FORCE_IPV4=0
    fi

fi

if [[ -z "$NETWORK_MODE" &&
      "$FORCE_IPV6" -eq 1 ]]
then

    echo "[Network] Checking IPv6..."

    if check_ipv6; then
        NETWORK_MODE="IPv6"
    else
        echo "ERROR: Forced IPv6 is unavailable." >&2
        exit 1
    fi

fi

if [[ -z "$NETWORK_MODE" ]]; then

    echo "[Network] AUTO detection..."

    if check_ipv4; then
        NETWORK_MODE="IPv4"
    elif check_ipv6; then
        NETWORK_MODE="IPv6"
    else
        echo "ERROR: No usable IPv4 or IPv6 route." >&2
        exit 1
    fi

fi

# ============================================================
# 6. De-duplicate SNI
# ============================================================

mapfile -t SNI_LIST < <(
    printf '%s\n' "${SNI_LIST[@]}" |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
        awk 'NF && !seen[$0]++'
)

SNI_COUNT="${#SNI_LIST[@]}"

if [[ "$SNI_COUNT" -eq 0 ]]; then
    echo "ERROR: SNI list is empty." >&2
    exit 1
fi

# ============================================================
# 7. Result directory
# ============================================================

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

RESULT_DIR="./reality-sni-v2.5.2_${TIMESTAMP}"

mkdir -p "$RESULT_DIR" || exit 1

FAST_RAW="$RESULT_DIR/fast_raw.txt"
FAST_STATS="$RESULT_DIR/fast_stats.txt"
FAST_RANKING="$RESULT_DIR/fast_ranking.txt"
FAST_RESULT="$RESULT_DIR/fast_result.txt"

TOP_FILE="$RESULT_DIR/top12.list"

PRECISION_RAW="$RESULT_DIR/precision_raw.txt"
PRECISION_STATS="$RESULT_DIR/precision_stats.txt"
PRECISION_RANKING="$RESULT_DIR/precision_ranking.txt"

FINAL_RESULT="$RESULT_DIR/final_ranking.txt"

RECOMMEND="$RESULT_DIR/recommended_sni.txt"
RECOMMENDED_LIST="$RESULT_DIR/recommended.list"

: > "$FAST_RAW"
: > "$FAST_STATS"
: > "$FAST_RANKING"
: > "$FAST_RESULT"
: > "$TOP_FILE"

: > "$PRECISION_RAW"
: > "$PRECISION_STATS"
: > "$PRECISION_RANKING"

: > "$FINAL_RESULT"
: > "$RECOMMEND"
: > "$RECOMMENDED_LIST"

# ============================================================
# 8. Export variables for child Bash processes
#
# IMPORTANT:
# xargs launches independent Bash processes.
# Explicit exports prevent NETWORK_MODE / timeout settings
# from disappearing inside test_one().
# ============================================================

export NETWORK_MODE
export FAST_TIMEOUT
export PRECISION_TIMEOUT

# ============================================================
# 9. Random pause helper
# ============================================================

random_range() {

    local min="$1"
    local max="$2"

    if (( max <= min )); then
        echo "$min"
    else
        echo $(( min + RANDOM % (max - min + 1) ))
    fi
}

# ============================================================
# 10. TLS 1.3 SNI test
#
# Output:
#
# domain|latency_ms|status
#
# Status:
#
# OK
# TIMEOUT
# RESET
# TLS_FAIL
# CERT_FAIL
# CONNECT_FAIL
# ============================================================

test_one() {

    local domain="${1:-}"
    local timeout_sec="${2:-3}"

    local start
    local end
    local elapsed

    local output
    local ret
    local status

    [[ -n "$domain" ]] || return 0

    start="$(date +%s%N 2>/dev/null)"

    if [[ "$NETWORK_MODE" == "IPv6" ]]; then

        output="$(
            timeout "${timeout_sec}s" \
                openssl s_client \
                    -6 \
                    -connect "${domain}:443" \
                    -servername "$domain" \
                    -tls1_3 \
                    -brief \
                    </dev/null 2>&1
        )"

        ret=$?

    elif [[ "$NETWORK_MODE" == "IPv4" ]]; then

        output="$(
            timeout "${timeout_sec}s" \
                openssl s_client \
                    -4 \
                    -connect "${domain}:443" \
                    -servername "$domain" \
                    -tls1_3 \
                    -brief \
                    </dev/null 2>&1
        )"

        ret=$?

    else

        output="$(
            timeout "${timeout_sec}s" \
                openssl s_client \
                    -connect "${domain}:443" \
                    -servername "$domain" \
                    -tls1_3 \
                    -brief \
                    </dev/null 2>&1
        )"

        ret=$?

    fi

    end="$(date +%s%N 2>/dev/null)"

    if [[ "$start" =~ ^[0-9]+$ &&
          "$end" =~ ^[0-9]+$ ]]
    then
        elapsed=$(( (end - start) / 1000000 ))
    else
        elapsed=999999
    fi

    status="CONNECT_FAIL"

    if [[ "$ret" -eq 124 ]]; then

        status="TIMEOUT"

    elif printf '%s\n' "$output" |
        grep -Eiq 'connection reset|reset by peer'
    then

        status="RESET"

    elif printf '%s\n' "$output" |
        grep -Eiq \
        'certificate verify failed|certificate verify error'
    then

        status="CERT_FAIL"

    elif printf '%s\n' "$output" |
        grep -Eiq \
        'handshake failure|SSL_ERROR|wrong version|no protocols'
    then

        status="TLS_FAIL"

    elif [[ "$ret" -eq 0 ]] &&
        printf '%s\n' "$output" |
        grep -Eiq \
        'Protocol version: TLSv1\.3|Ciphersuite: TLS_'
    then

        status="OK"

    else

        status="CONNECT_FAIL"

    fi

    printf '%s|%s|%s\n' \
        "$domain" \
        "$elapsed" \
        "$status"
}

export -f test_one

# ============================================================
# 11. Banner
# ============================================================

echo
echo "============================================================"
echo " Reality SNI Tester v$VERSION"
echo "============================================================"
echo

echo "Bash             : $BASH_VERSION"
echo "Network Mode     : $NETWORK_MODE"
echo "SNI Count        : $SNI_COUNT"

echo
echo "Fast Screening"
echo "  Rounds         : $FAST_ROUNDS"
echo "  Concurrency    : $FAST_CONC"
echo "  Timeout        : ${FAST_TIMEOUT}s"

echo
echo "Precision"
echo "  TOP            : $PRECISION_TOP"
echo "  Rounds         : $PRECISION_ROUNDS"
echo "  Concurrency    : $PRECISION_CONC"
echo "  Timeout        : ${PRECISION_TIMEOUT}s"

echo
echo "PASS"
echo "  Success        : >= ${PASS_SUCCESS}%"
echo "  P95            : <= ${PASS_P95}ms"
echo "  P99            : <= ${PASS_P99}ms"
echo "  Risk           : <= ${PASS_RISK}"

echo
echo "WARN"
echo "  Success        : >= ${WARN_SUCCESS}%"
echo "  P95            : <= ${WARN_P95}ms"
echo "  P99            : <= ${WARN_P99}ms"
echo "  Risk           : <= ${WARN_RISK}"

echo
echo "Result Directory:"
echo "  $RESULT_DIR"

echo
echo "============================================================"
echo

# ============================================================
# 12. Fast screening
# ============================================================

echo "[1/2] Fast Screening"
echo

FAST_START="$(date +%s)"

for ((round=1; round<=FAST_ROUNDS; round++)); do

    echo "Fast Round $round / $FAST_ROUNDS"

    printf '%s\n' "${SNI_LIST[@]}" |
        xargs -r -I{} \
            -P "$FAST_CONC" \
            bash -c \
            'test_one "$1" "$FAST_TIMEOUT"' \
            _ {} \
            >> "$FAST_RAW"

done

FAST_END="$(date +%s)"

echo
echo "Fast screening completed."
echo "Elapsed: $((FAST_END-FAST_START)) seconds"
echo

# ============================================================
# 13. Fast statistics
# ============================================================

while IFS= read -r domain; do

    [[ -n "$domain" ]] || continue

    total="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d{n++} END{print n+0}' \
            "$FAST_RAW"
    )"

    success="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="OK"{n++} END{print n+0}' \
            "$FAST_RAW"
    )"

    rate="$(
        awk \
            -v s="$success" \
            -v t="$total" \
            'BEGIN{
                if(t>0)
                    printf "%.2f",s/t*100
                else
                    print "0.00"
            }'
    )"

    avg="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="OK"{sum+=$2;n++}
             END{
                 if(n>0)
                     printf "%.2f",sum/n
                 else
                     print 999999
             }' \
            "$FAST_RAW"
    )"

    printf '%s|%s|%s|%s\n' \
        "$domain" \
        "$success" \
        "$rate" \
        "$avg" \
        >> "$FAST_STATS"

done < <(
    printf '%s\n' "${SNI_LIST[@]}"
)

# ============================================================
# 14. Fast ranking
# ============================================================

sort \
    -t'|' \
    -k3,3nr \
    -k4,4n \
    "$FAST_STATS" \
    > "$FAST_RANKING"

{
    echo "============================================================"
    echo " FAST SCREENING RESULT"
    echo "============================================================"
    echo

    printf "%-50s %10s %10s %12s\n" \
        "SNI" \
        "SUCCESS" \
        "RATE" \
        "AVG(ms)"

    echo "-------------------------------------------------------------------------------"

    while IFS='|' read -r \
        domain \
        success \
        rate \
        avg
    do

        printf "%-50s %3s/%-3s %9s%% %10sms\n" \
            "$domain" \
            "$success" \
            "$FAST_ROUNDS" \
            "$rate" \
            "$avg"

    done < "$FAST_RANKING"

    echo

} | tee "$FAST_RESULT"

# ============================================================
# 15. TOP12
# ============================================================

head -n "$PRECISION_TOP" \
    "$FAST_RANKING" |
    cut -d'|' -f1 \
    > "$TOP_FILE"

echo
echo "============================================================"
echo " PRECISION TOP$PRECISION_TOP"
echo "============================================================"
echo

nl -ba "$TOP_FILE"

echo

# ============================================================
# 16. Percentile calculation
#
# P50 / P75 / P90 / P95 / P99
# ============================================================

percentile() {

    local domain="$1"
    local pct="$2"

    awk -F'|' \
        -v d="$domain" \
        -v p="$pct" '

        $1==d && $3=="OK" {
            a[++n]=$2
        }

        END {

            if(n==0) {
                print 999999
                exit
            }

            # Portable insertion sort.
            # No gawk-only asort() dependency.

            for(i=2;i<=n;i++) {

                value=a[i]
                j=i-1

                while(j>=1 && a[j]>value) {

                    a[j+1]=a[j]
                    j--

                }

                a[j+1]=value

            }

            pos=int((n*p + 99)/100)

            if(pos<1)
                pos=1

            if(pos>n)
                pos=n

            print a[pos]

        }

    ' "$PRECISION_RAW"
}

# ============================================================
# 17. Jitter
#
# Definition:
#
# Average absolute difference between consecutive successful
# latency samples in chronological order.
#
# This is a more meaningful time-series jitter indicator than
# simply using P95-P50.
# ============================================================

calc_jitter() {

    local domain="$1"

    awk -F'|' \
        -v d="$domain" '

        $1==d && $3=="OK" {

            current=$2

            if(have_previous) {

                diff=current-previous

                if(diff<0)
                    diff=-diff

                sum+=diff
                count++

            }

            previous=current
            have_previous=1
        }

        END {

            if(count>0)
                printf "%.2f\n",sum/count
            else
                print 999999

        }

    ' "$PRECISION_RAW"
}

# ============================================================
# 18. Risk penalty
#
# Risk is based only on observed test failures.
#
# TIMEOUT       = 1.00
# RESET         = 1.50
# TLS_FAIL      = 1.00
# CERT_FAIL     = 0.50
# CONNECT_FAIL  = 0.50
#
# Maximum penalty = 20
# ============================================================

calc_risk() {

    local domain="$1"

    awk -F'|' \
        -v d="$domain" '

        $1==d {

            total++

            if($3=="TIMEOUT")
                timeout++

            else if($3=="RESET")
                reset++

            else if($3=="TLS_FAIL")
                tlsfail++

            else if($3=="CERT_FAIL")
                certfail++

            else if($3=="CONNECT_FAIL")
                connectfail++

        }

        END {

            risk=0

            if(total>0) {

                risk += timeout/total*100*1.0
                risk += reset/total*100*1.5
                risk += tlsfail/total*100*1.0
                risk += certfail/total*100*0.5
                risk += connectfail/total*100*0.5

            }

            if(risk>20)
                risk=20

            printf "%.2f\n",risk

        }

    ' "$PRECISION_RAW"
}

# ============================================================
# 19. Score
#
# Maximum = 100
#
# Stability / Success     50
# P95                     20
# P50                     10
# P99                     10
# Jitter                  10
# Risk penalty            deducted
#
# The score is clamped to 0..100.
# ============================================================

calc_score() {

    local rate="$1"
    local p50="$2"
    local p95="$3"
    local p99="$4"
    local jitter="$5"
    local risk="$6"

    awk \
        -v rate="$rate" \
        -v p50="$p50" \
        -v p95="$p95" \
        -v p99="$p99" \
        -v jitter="$jitter" \
        -v risk="$risk" '

        BEGIN {

            # ------------------------------------------------
            # Success / stability: 50 points
            # ------------------------------------------------

            stability=(rate/100)*50

            # ------------------------------------------------
            # P95: 20 points
            # ------------------------------------------------

            if(p95<=200)
                s95=20
            else if(p95<=300)
                s95=19
            else if(p95<=500)
                s95=17
            else if(p95<=700)
                s95=14
            else if(p95<=1000)
                s95=8
            else if(p95<=1500)
                s95=3
            else
                s95=0

            # ------------------------------------------------
            # P50: 10 points
            # ------------------------------------------------

            if(p50<=100)
                s50=10
            else if(p50<=200)
                s50=9
            else if(p50<=300)
                s50=8
            else if(p50<=500)
                s50=6
            else if(p50<=800)
                s50=3
            else
                s50=0

            # ------------------------------------------------
            # P99: 10 points
            # ------------------------------------------------

            if(p99<=300)
                s99=10
            else if(p99<=500)
                s99=9
            else if(p99<=1000)
                s99=7
            else if(p99<=1500)
                s99=5
            else if(p99<=2000)
                s99=2
            else
                s99=0

            # ------------------------------------------------
            # Jitter: 10 points
            # ------------------------------------------------

            if(jitter<=20)
                sj=10
            else if(jitter<=50)
                sj=9
            else if(jitter<=100)
                sj=8
            else if(jitter<=150)
                sj=6
            else if(jitter<=300)
                sj=4
            else if(jitter<=500)
                sj=2
            else
                sj=0

            # ------------------------------------------------
            # Risk penalty
            # ------------------------------------------------

            final=stability+s95+s50+s99+sj-risk

            if(final<0)
                final=0

            if(final>100)
                final=100

            printf "%.2f\n",final

        }

    '
}

# ============================================================
# 20. Verdict
# ============================================================

calc_verdict() {

    local rate="$1"
    local p95="$2"
    local p99="$3"
    local risk="$4"

    awk \
        -v rate="$rate" \
        -v p95="$p95" \
        -v p99="$p99" \
        -v risk="$risk" \
        -v pass_rate="$PASS_SUCCESS" \
        -v pass_p95="$PASS_P95" \
        -v pass_p99="$PASS_P99" \
        -v pass_risk="$PASS_RISK" \
        -v warn_rate="$WARN_SUCCESS" \
        -v warn_p95="$WARN_P95" \
        -v warn_p99="$WARN_P99" \
        -v warn_risk="$WARN_RISK" '

        BEGIN {

            if(rate>=pass_rate &&
               p95<=pass_p95 &&
               p99<=pass_p99 &&
               risk<=pass_risk)
            {
                print "PASS"
                exit
            }

            if(rate>=warn_rate &&
               p95<=warn_p95 &&
               p99<=warn_p99 &&
               risk<=warn_risk)
            {
                print "WARN"
                exit
            }

            print "FAIL"
        }

    '
}

# ============================================================
# 21. Precision testing
# ============================================================

echo "============================================================"
echo " PRECISION TEST"
echo "============================================================"
echo

PRECISION_START="$(date +%s)"

: > "$PRECISION_RAW"

while IFS= read -r domain; do

    [[ -n "$domain" ]] || continue

    echo "Testing: $domain"

    for ((round=1; round<=PRECISION_ROUNDS; round++)); do

        printf '\r  Round %3d / %3d' \
            "$round" \
            "$PRECISION_ROUNDS"

        test_one \
            "$domain" \
            "$PRECISION_TIMEOUT" \
            >> "$PRECISION_RAW"

        if (( round < PRECISION_ROUNDS )); then

            pause="$(
                random_range \
                    "$ROUND_PAUSE_MIN" \
                    "$ROUND_PAUSE_MAX"
            )"

            sleep "$pause"

        fi

        if (( round % BATCH_SIZE == 0 &&
              round < PRECISION_ROUNDS ))
        then

            echo
            echo "  Batch pause..."

            pause="$(
                random_range \
                    "$BATCH_PAUSE_MIN" \
                    "$BATCH_PAUSE_MAX"
            )"

            sleep "$pause"

        fi

    done

    echo
    echo

done < "$TOP_FILE"

PRECISION_END="$(date +%s)"

echo "Precision testing completed."
echo "Elapsed: $((PRECISION_END-PRECISION_START)) seconds"
echo

# ============================================================
# 22. Precision statistics
#
# Fields:
#
# 1  domain
# 2  rate
# 3  avg
# 4  p50
# 5  p75
# 6  p90
# 7  p95
# 8  p99
# 9  jitter
# 10 timeout_count
# 11 reset_count
# 12 tlsfail_count
# 13 certfail_count
# 14 connectfail_count
# 15 risk
# 16 score
# 17 verdict
# ============================================================

while IFS= read -r domain; do

    [[ -n "$domain" ]] || continue

    total="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    success="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="OK"{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    rate="$(
        awk \
            -v s="$success" \
            -v t="$total" \
            'BEGIN{
                if(t>0)
                    printf "%.2f",s/t*100
                else
                    print "0.00"
            }'
    )"

    avg="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="OK"{sum+=$2;n++}
             END{
                 if(n>0)
                     printf "%.2f",sum/n
                 else
                     print 999999
             }' \
            "$PRECISION_RAW"
    )"

    p50="$(percentile "$domain" 50)"
    p75="$(percentile "$domain" 75)"
    p90="$(percentile "$domain" 90)"
    p95="$(percentile "$domain" 95)"
    p99="$(percentile "$domain" 99)"

    jitter="$(calc_jitter "$domain")"

    timeout_count="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="TIMEOUT"{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    reset_count="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="RESET"{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    tlsfail_count="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="TLS_FAIL"{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    certfail_count="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="CERT_FAIL"{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    connectfail_count="$(
        awk -F'|' \
            -v d="$domain" \
            '$1==d && $3=="CONNECT_FAIL"{n++} END{print n+0}' \
            "$PRECISION_RAW"
    )"

    risk="$(calc_risk "$domain")"

    score="$(
        calc_score \
            "$rate" \
            "$p50" \
            "$p95" \
            "$p99" \
            "$jitter" \
            "$risk"
    )"

    verdict="$(
        calc_verdict \
            "$rate" \
            "$p95" \
            "$p99" \
            "$risk"
    )"

    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$domain" \
        "$rate" \
        "$avg" \
        "$p50" \
        "$p75" \
        "$p90" \
        "$p95" \
        "$p99" \
        "$jitter" \
        "$timeout_count" \
        "$reset_count" \
        "$tlsfail_count" \
        "$certfail_count" \
        "$connectfail_count" \
        "$risk" \
        "$score" \
        "$verdict" \
        >> "$PRECISION_STATS"

done < "$TOP_FILE"

# ============================================================
# 23. Correct final ranking
#
# Internal sort fields after adding priority:
#
# 1  priority
# 2  domain
# 3  rate
# 4  avg
# 5  p50
# 6  p75
# 7  p90
# 8  p95
# 9  p99
# 10 jitter
# 11 timeout
# 12 reset
# 13 tlsfail
# 14 certfail
# 15 connectfail
# 16 risk
# 17 score
# 18 verdict
#
# Priority:
#
# PASS = 1
# WARN = 2
# FAIL = 3
#
# Then:
#
# Score DESC
# P95 ASC
# P99 ASC
# Success Rate DESC
# ============================================================

awk -F'|' '

{
    if($17=="PASS")
        priority=1
    else if($17=="WARN")
        priority=2
    else
        priority=3

    print priority "|" $0
}

' "$PRECISION_STATS" |
sort \
    -t'|' \
    -k1,1n \
    -k17,17nr \
    -k8,8n \
    -k9,9n \
    -k3,3nr |
cut -d'|' -f2- \
> "$PRECISION_RANKING"

# ============================================================
# 24. Final ranking display
# ============================================================

{
    echo
    echo "============================================================"
    echo " FINAL RANKING"
    echo "============================================================"
    echo

    printf "%-35s %7s %8s %7s %7s %7s %7s %7s %8s %7s %8s %8s\n" \
        "SNI" \
        "RATE" \
        "AVG" \
        "P50" \
        "P75" \
        "P90" \
        "P95" \
        "P99" \
        "JITTER" \
        "RISK" \
        "SCORE" \
        "STATUS"

    echo "----------------------------------------------------------------------------------------------------------------------------------"

    while IFS='|' read -r \
        domain \
        rate \
        avg \
        p50 \
        p75 \
        p90 \
        p95 \
        p99 \
        jitter \
        timeout_count \
        reset_count \
        tlsfail_count \
        certfail_count \
        connectfail_count \
        risk \
        score \
        verdict
    do

        printf "%-35s %6s%% %8sms %7sms %7sms %7sms %7sms %7sms %8sms %7s %8s %8s\n" \
            "$domain" \
            "$rate" \
            "$avg" \
            "$p50" \
            "$p75" \
            "$p90" \
            "$p95" \
            "$p99" \
            "$jitter" \
            "$risk" \
            "$score" \
            "$verdict"

    done < "$PRECISION_RANKING"

    echo

} | tee "$FINAL_RESULT"

# ============================================================
# 25. Recommendation
#
# Only PASS entries are considered actual recommendations.
#
# WARN is shown in the ranking but is NOT automatically promoted
# to PRIMARY / BACKUP.
# ============================================================

PASS_FILE="$RESULT_DIR/pass.list"

awk -F'|' \
    '$17=="PASS"{print}' \
    "$PRECISION_RANKING" \
    > "$PASS_FILE"

PRIMARY=""
BACKUP=""
BACKUP2=""

if [[ -s "$PASS_FILE" ]]; then

    PRIMARY="$(
        sed -n '1p' "$PASS_FILE" |
            cut -d'|' -f1
    )"

    BACKUP="$(
        sed -n '2p' "$PASS_FILE" |
            cut -d'|' -f1
    )"

    BACKUP2="$(
        sed -n '3p' "$PASS_FILE" |
            cut -d'|' -f1
    )"

fi

# ============================================================
# 26. Human-readable recommendation
# ============================================================

{

    echo
    echo "============================================================"
    echo " RECOMMENDED SNI"
    echo "============================================================"
    echo

    echo "Network Mode : $NETWORK_MODE"
    echo

    echo "PRIMARY"
    echo "-------"

    if [[ -n "$PRIMARY" ]]; then

        awk -F'|' \
            -v d="$PRIMARY" '

            $1==d {

                printf "SNI   : %s\n", $1
                printf "Score : %s\n", $16
                printf "Status: %s\n", $17
                printf "Rate  : %s%%\n", $2
                printf "P50   : %sms\n", $4
                printf "P75   : %sms\n", $5
                printf "P90   : %sms\n", $6
                printf "P95   : %sms\n", $7
                printf "P99   : %sms\n", $8
                printf "Jitter: %sms\n", $9
                printf "Risk  : %s\n", $15

            }

            ' "$PRECISION_RANKING"

    else

        echo "NONE"

    fi

    echo
    echo "BACKUP"
    echo "------"

    if [[ -n "$BACKUP" ]]; then

        awk -F'|' \
            -v d="$BACKUP" '

            $1==d {

                printf "SNI   : %s\n", $1
                printf "Score : %s\n", $16
                printf "Status: %s\n", $17
                printf "Rate  : %s%%\n", $2
                printf "P50   : %sms\n", $4
                printf "P75   : %sms\n", $5
                printf "P90   : %sms\n", $6
                printf "P95   : %sms\n", $7
                printf "P99   : %sms\n", $8
                printf "Jitter: %sms\n", $9
                printf "Risk  : %s\n", $15

            }

            ' "$PRECISION_RANKING"

    else

        echo "NONE"

    fi

    echo
    echo "BACKUP2"
    echo "-------"

    if [[ -n "$BACKUP2" ]]; then

        awk -F'|' \
            -v d="$BACKUP2" '

            $1==d {

                printf "SNI   : %s\n", $1
                printf "Score : %s\n", $16
                printf "Status: %s\n", $17
                printf "Rate  : %s%%\n", $2
                printf "P50   : %sms\n", $4
                printf "P75   : %sms\n", $5
                printf "P90   : %sms\n", $6
                printf "P95   : %sms\n", $7
                printf "P99   : %sms\n", $8
                printf "Jitter: %sms\n", $9
                printf "Risk  : %s\n", $15

            }

            ' "$PRECISION_RANKING"

    else

        echo "NONE"

    fi

    echo
    echo "============================================================"
    echo " PASS Criteria"
    echo "============================================================"
    echo

    echo "Success Rate >= ${PASS_SUCCESS}%"
    echo "P95           <= ${PASS_P95}ms"
    echo "P99           <= ${PASS_P99}ms"
    echo "Risk          <= ${PASS_RISK}"

    echo
    echo "============================================================"
    echo " serverNames Candidates"
    echo "============================================================"
    echo

    [[ -n "$PRIMARY" ]] && echo "$PRIMARY"
    [[ -n "$BACKUP" ]] && echo "$BACKUP"
    [[ -n "$BACKUP2" ]] && echo "$BACKUP2"

    echo

} | tee "$RECOMMEND"

# ============================================================
# 27. Machine-readable recommendation list
# ============================================================

{
    [[ -n "$PRIMARY" ]] && echo "$PRIMARY"
    [[ -n "$BACKUP" ]] && echo "$BACKUP"
    [[ -n "$BACKUP2" ]] && echo "$BACKUP2"

} > "$RECOMMENDED_LIST"

# ============================================================
# 28. Final summary
# ============================================================

FAST_REQUESTS="$(
    wc -l < "$FAST_RAW"
)"

FAST_SUCCESS="$(
    awk -F'|' \
        '$3=="OK"{n++} END{print n+0}' \
        "$FAST_RAW"
)"

PRECISION_REQUESTS="$(
    wc -l < "$PRECISION_RAW"
)"

TOTAL_REQUESTS="$(
    awk \
        -v a="$FAST_REQUESTS" \
        -v b="$PRECISION_REQUESTS" \
        'BEGIN{print a+b}'
)"

PASS_COUNT="$(
    awk -F'|' \
        '$17=="PASS"{n++} END{print n+0}' \
        "$PRECISION_RANKING"
)"

WARN_COUNT="$(
    awk -F'|' \
        '$17=="WARN"{n++} END{print n+0}' \
        "$PRECISION_RANKING"
)"

FAIL_COUNT="$(
    awk -F'|' \
        '$17=="FAIL"{n++} END{print n+0}' \
        "$PRECISION_RANKING"
)"

echo
echo "============================================================"
echo " TEST COMPLETE"
echo "============================================================"
echo

echo "Version                  : $VERSION"
echo "Network Mode             : $NETWORK_MODE"
echo "Unique SNI               : $SNI_COUNT"

echo
echo "Fast Requests            : $FAST_REQUESTS"
echo "Fast Successful          : $FAST_SUCCESS"

echo
echo "Precision Requests       : $PRECISION_REQUESTS"
echo "Total Requests           : $TOTAL_REQUESTS"

echo
echo "PASS                     : $PASS_COUNT"
echo "WARN                     : $WARN_COUNT"
echo "FAIL                     : $FAIL_COUNT"

echo
echo "------------------------------------------------------------"
echo " RECOMMENDED"
echo "------------------------------------------------------------"

echo
echo "PRIMARY                  : ${PRIMARY:-NONE}"
echo "BACKUP                   : ${BACKUP:-NONE}"
echo "BACKUP2                  : ${BACKUP2:-NONE}"

echo
echo "------------------------------------------------------------"
echo " RESULT FILES"
echo "------------------------------------------------------------"

echo
echo "Final Ranking            : $FINAL_RESULT"
echo "Precision Ranking        : $PRECISION_RANKING"
echo "Recommendation           : $RECOMMEND"
echo "Machine List             : $RECOMMENDED_LIST"

echo
echo "============================================================"
echo " All tests completed."
echo "============================================================"
echo