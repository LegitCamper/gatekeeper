#!/usr/bin/env bash
# Drives POST /scan with ~100 PII cases and prints what each one sanitizes to.
#
#   tests/sanitize.sh                         # build, start, print all cases, tear down
#   URL=http://host:8080 tests/sanitize.sh    # run against an already-running server
#
# Each case is `expected|text`, where expected is a comma-separated list of
# detector categories in order of appearance, or `-` for "must detect nothing".
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
url=${URL:-}
server_pid=""

cleanup() {
	[[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null
	return 0
}
trap cleanup EXIT

if [[ -z $url ]]; then
	echo "building..." >&2
	cargo build --quiet --release --manifest-path "$root/Cargo.toml" || exit 1

	port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
	url="http://127.0.0.1:$port"
	LISTEN_ADDR="127.0.0.1:$port" RUST_LOG=error "$root/target/release/gatekeeper" &>/dev/null &
	server_pid=$!

	for _ in $(seq 50); do
		curl -sf "$url/health" &>/dev/null && break
		sleep 0.1
	done
	if ! curl -sf "$url/health" &>/dev/null; then
		echo "server never became healthy at $url" >&2
		exit 1
	fi
fi

# expected|text
cases=(
	# --- Email -------------------------------------------------------------
	'email|mail alice@example.com today'
	'email|mail a.b+tag@example.co.uk today'
	'email|mail first.last@sub.domain.example.org today'
	'email|mail user_name@example-corp.com today'
	'email|mail UPPER@EXAMPLE.COM today'
	'email|mail x@y.io today'
	'email|mail 12345@numeric.net today'
	'email|mail a%b@percent.com today'
	'email|contact: bob@corp.io.'
	'email|<carol@example.com>'
	'email,email|cc dev@a.com and ops@b.com'
	'email|"email":"dana@example.com"'
	'-|not an email: user@localhost'
	'-|a @ b . com'
	'-|100% @ capacity'

	# --- Phone: North American --------------------------------------------
	'phone|call 4155552671 now'
	'phone|call 415-555-2671 now'
	'phone|call 415.555.2671 now'
	'phone|call 415 555 2671 now'
	'phone|call (415) 555-2671 now'
	'phone|call (415)555-2671 now'
	'phone|call 14155552671 now'
	'phone|call 1-415-555-2671 now'
	'phone|call +14155552671 now'
	'phone|call +1 415 555 2671 now'
	'phone|call +1 (415) 555-2671 now'
	'phone|call +1-415-555-2671 now'
	'phone|call 000-000-0000 now'
	'-|call 555-0100-999 now'
	'phone|tel: 2125551234'

	# --- Phone: international ---------------------------------------------
	'phone|call +44 20 7946 0958 now'
	'phone|call +442079460958 now'
	'phone|call +33 6 12 34 56 78 now'
	'phone|call +49 30 12345678 now'
	'phone|call +81 3 1234 5678 now'
	'phone|call +61 2 9374 4000 now'
	'phone|call +91 98765 43210 now'
	'phone|call +55 11 91234 5678 now'
	'phone|call +7 495 123 45 67 now'
	'phone|call +86 138 0013 8000 now'

	# --- Phone: Vietnamese -------------------------------------------------
	'phone|call +84 91 234 56 78 now'
	'phone|call +84 912 345 678 now'
	'phone|call 0912345678 now'
	# Invalid 12-digit pseudo-prefix: valid forms are 0912345678 or +84 912345678.
	'-|call 084 912 345 678 now'
	'phone|goi 0987654321 nhe'

	# --- Phone: must NOT match --------------------------------------------
	'-|port 8080 timeout 30000'
	'-|version 1 2 3 build 4'
	'-|count 12345 items'
	'-|error code 500 retry 3'
	'-|id 42 of 100'

	# --- SSN ---------------------------------------------------------------
	'ssn|ssn 123-45-6789 on file'
	'ssn|SSN: 001-01-0001'
	'ssn|taxpayer 987-65-4321 verified'
	'ssn|"ssn":"123-45-6789"'
	'ssn|123-45-6789'
	'ssn|(123-45-6789)'
	'-|order 123-45-678 shipped'
	'-|range 1234-56-78901'

	# --- Credit cards ------------------------------------------------------
	'credit_card|card 4111111111111111 ok'
	'credit_card|card 4111 1111 1111 1111 ok'
	'credit_card|card 4111-1111-1111-1111 ok'
	'credit_card|visa 4012888888881881 charged'
	'credit_card|mc 5555555555554444 charged'
	'credit_card|mc 5105 1051 0510 5100 charged'
	'credit_card|amex 378282246310005 charged'
	'credit_card|amex 3782 822463 10005 charged'
	'credit_card|discover 6011111111111117 charged'
	'credit_card|jcb 3530111333300000 charged'
	'credit_card|diners 30569309025904 charged'
	'credit_card|"number":"4111111111111111"'
	'-|order 1234567812345678 shipped'
	'-|invoice 9999999999999999 paid'
	# Luhn-valid: detector cannot distinguish this digit string from a real card.
	'credit_card|sku 1111222233334444 stocked'

	# --- Names: dictionary -------------------------------------------------
	'name|ping Alice Johnson today'
	'name|ping Xiulan Wang today'
	'name|ping Dmitri Volkov today'
	'name|ping Hiroshi Tanaka today'
	'name|ping Priya Sharma today'
	'name|ping Aisha Okonkwo today'
	'name|ping Lars Andersen today'
	'name|ping Yusuf Demir today'
	'name|ping Nguyen Van today'
	'name|ping John Smith today'

	# --- Names: trigger words ---------------------------------------------
	'name|contact Zephyr Quixotic'
	'name|cc: Blorbo Fnargle'
	'name|regards, Quintus Vibrissae'
	'name|attn Marlowe Underbough'
	'name|sincerely, Octavia Wrenfield'
	'name|signed Percival Thistlewood'
	'name|my name is Quentin Farsworth'
	'name|Name: Ludovic Beaumarchais'
	'name|Dr. Ingrid Sorensen'
	'name|Mr. Fitzgerald Ashworth'
	'name|Mrs. Beatrice Hollowell'
	'name|Ms. Rosalind Fairweather'

	# --- Names: must NOT match --------------------------------------------
	'-|Deploy to New York using Docker Compose'
	'-|Error: Connection Refused from Redis Cluster'
	'-|The Rust Foundation released Cargo Nightly'
	'-|Meeting on Monday March about the migration'
	'-|North America and South Africa regions'
	'-|Pull Request Merged by GitHub Actions'
	'-|Use Visual Studio Code on Mac OS'
	'-|Read the Apache License before merging'
	'-|SELECT id FROM users WHERE age > 18'
	'-|See Chapter Four of the Design Doc'

	# --- Mixed / adversarial ----------------------------------------------
	'name,email|Email Alice Johnson at alice@example.com'
	'name,email,phone|Alice Johnson, alice@example.com, 415-555-2671'
	'email,credit_card|billing@corp.com card 4111111111111111'
	'ssn,credit_card|ssn 123-45-6789 card 4111111111111111'
	'name,phone|contact Zephyr Quixotic at +44 20 7946 0958'
	'email|Chào bạn, thư alice@example.com nhé ✅'
	'name,email|{"user":"Alice Johnson","mail":"alice@example.com"}'
	'-|summarize the quarterly report'
	'-|'
)

pad() { printf '%-14s' "$1"; }

pass=0
fail=0
failed_output=""

for entry in "${cases[@]}"; do
	expected=${entry%%|*}
	text=${entry#*|}

	response=$(jq -nc --arg t "$text" '{text:$t}' |
		curl -sf --max-time 10 -X POST "$url/scan" \
			-H 'content-type: application/json' --data-binary @-)
	if [[ -z $response ]]; then
		printf '  ERROR   %s\n' "$text"
		fail=$((fail + 1))
		continue
	fi

	actual=$(jq -r '[.matches[].kind] | join(",")' <<<"$response")
	[[ -z $actual ]] && actual="-"
	sanitized=$(jq -r '.anonymized.text' <<<"$response")

	if [[ $actual == "$expected" ]]; then
		pass=$((pass + 1))
		printf '  \033[32mok\033[0m      %s%s -> %s\n' "$(pad "$actual")" "$text" "$sanitized"
	else
		fail=$((fail + 1))
		failed_output+=$(printf '  \033[31mFAIL\033[0m    %s\n            expected: %s\n            actual:   %s\n            -> %s\n' \
			"$text" "$expected" "$actual" "$sanitized")
		failed_output+=$'\n'
	fi
done

echo
[[ -n $failed_output ]] && printf '%s' "$failed_output"
printf 'total %d, passed %d, failed %d\n' "$((pass + fail))" "$pass" "$fail"
((fail == 0))
