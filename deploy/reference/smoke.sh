#!/usr/bin/env bash
# Topology smoke check for the Vinctor production reference stack (PKA-33).
#
# Verifies the *deployment surface* against the real service, complementing the
# authz smoke in deploy/preview/smoke.py (which drives enforce/audit and needs
# keys). This one needs no keys, so it can run against any reachable instance:
#
#   - GET /healthz  -> 200 and {"status":"ok"}   (liveness)
#   - GET /readyz   -> 200 and {"status":"ready"} (readiness; SELECT 1 on the store)
#   - GET /metrics  -> reachability matches the --metrics expectation
#
# Usage:
#   deploy/reference/smoke.sh --endpoint https://vinctor.example.com
#   deploy/reference/smoke.sh --endpoint https://localhost --insecure --metrics blocked
#   deploy/reference/smoke.sh --endpoint http://127.0.0.1:8765 --metrics open
#
# --metrics open    : expect /metrics to return 200 (scraped in-network).
# --metrics blocked : expect /metrics to be refused at the edge (non-200).
# --metrics skip    : do not check /metrics (default).
#
# --anchor-file PATH: also assert the audit chain-head anchor file exists and is
#                     non-empty. Run this AFTER some audited activity (an enforce
#                     or a grant), from where PATH is visible (inside the vinctor
#                     container the reference stack uses /data/chain-heads.jsonl).
#                     It guards the fail-open case where an unwritable sink leaves
#                     the tamper-evidence stream silently empty.
#
# Against the reference compose stack, the edge is HTTPS and Caddy blocks
# /metrics, so use `--metrics blocked`. A running stack needs Docker, so this
# script is not exercised in CI; the underlying endpoints are covered by the
# in-repo tests in tests/test_preview_deployment.py.
#
# Fails closed: any unreachable endpoint or unexpected status exits non-zero.
set -euo pipefail

endpoint=""
metrics="skip"
insecure=0
anchor_file=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--endpoint)
		endpoint="${2:-}"
		shift 2
		;;
	--metrics)
		metrics="${2:-}"
		shift 2
		;;
	--anchor-file)
		anchor_file="${2:-}"
		shift 2
		;;
	--insecure)
		insecure=1
		shift
		;;
	*)
		echo "smoke: unknown argument: $1" >&2
		exit 2
		;;
	esac
done

if [[ -z "$endpoint" ]]; then
	echo "smoke: --endpoint is required" >&2
	exit 2
fi
case "$metrics" in
open | blocked | skip) ;;
*)
	echo "smoke: --metrics must be one of open|blocked|skip" >&2
	exit 2
	;;
esac

curl_opts=(--silent --show-error --max-time 10)
if [[ "$insecure" -eq 1 ]]; then
	curl_opts+=(--insecure)
fi

base="${endpoint%/}"

# Prints "HTTP_STATUS\nBODY". Returns curl's own exit on a transport failure so
# a refused connection or timeout fails the smoke rather than passing silently.
fetch() {
	local path="$1"
	curl "${curl_opts[@]}" --write-out '\n%{http_code}' "${base}${path}"
}

check_json_field() {
	# check_json_field <path> <expected_status> <field> <expected_value>
	local path="$1" want_status="$2" field="$3" want_value="$4"
	local out status body value
	out="$(fetch "$path")"
	status="${out##*$'\n'}"
	body="${out%$'\n'*}"
	if [[ "$status" != "$want_status" ]]; then
		echo "smoke: ${path} returned HTTP ${status}, expected ${want_status}" >&2
		echo "  body: ${body}" >&2
		return 1
	fi
	# Extract "field":"value" without a JSON parser (bodies are tiny + flat).
	value="$(printf '%s' "$body" | sed -n "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p")"
	if [[ "$value" != "$want_value" ]]; then
		echo "smoke: ${path} ${field}=\"${value}\", expected \"${want_value}\"" >&2
		echo "  body: ${body}" >&2
		return 1
	fi
	echo "smoke: ${path} OK (${field}=${value})"
}

check_metrics() {
	local out status
	out="$(fetch /metrics)"
	status="${out##*$'\n'}"
	case "$metrics" in
	open)
		if [[ "$status" != "200" ]]; then
			echo "smoke: /metrics returned HTTP ${status}, expected 200 (--metrics open)" >&2
			return 1
		fi
		echo "smoke: /metrics reachable (HTTP 200)"
		;;
	blocked)
		if [[ "$status" == "200" ]]; then
			echo "smoke: /metrics returned HTTP 200 but must be blocked at the edge" >&2
			return 1
		fi
		echo "smoke: /metrics blocked at the edge (HTTP ${status})"
		;;
	esac
}

check_anchor_file() {
	# The anchor is fail-open: an unwritable sink drops every line silently. If
	# the file is missing or empty after audited activity, the tamper-evidence
	# stream is not being recorded — fail closed.
	if [[ ! -e "$anchor_file" ]]; then
		echo "smoke: anchor file ${anchor_file} does not exist (sink unwritable, or no audited activity yet)" >&2
		return 1
	fi
	if [[ ! -s "$anchor_file" ]]; then
		echo "smoke: anchor file ${anchor_file} is empty (sink unwritable, or no audited activity yet)" >&2
		return 1
	fi
	echo "smoke: anchor file ${anchor_file} OK ($(wc -l <"$anchor_file" | tr -d ' ') lines)"
}

check_json_field /healthz 200 status ok
check_json_field /readyz 200 status ready
if [[ "$metrics" != "skip" ]]; then
	check_metrics
fi
if [[ -n "$anchor_file" ]]; then
	check_anchor_file
fi

echo "ALL REFERENCE TOPOLOGY SMOKE STEPS PASSED"
