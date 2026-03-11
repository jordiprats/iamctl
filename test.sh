#!/bin/bash
set -euo pipefail

BINARY="./dist/iam-pb-check"
TESTDATA="./testdata"
TMPDIR_TEST=$(mktemp -d)

trap 'rm -rf "$TMPDIR_TEST"' EXIT

PASSED=0
FAILED=0

pass() { echo "✅ $1"; PASSED=$((PASSED + 1)); }
fail() { echo "❌ $1"; FAILED=$((FAILED + 1)); }

# -----------------------------------------------------------------------
# Build (if binary doesn't already exist)
# -----------------------------------------------------------------------
if [ ! -x "$BINARY" ]; then
  echo "Building iam-pb-check..."
  go build -o dist/iam-pb-check main.go
fi

VER=$($BINARY -v | head -n1)
if [[ "$VER" == *"iam-pb-check version"* ]]; then
  pass "Version output looks correct: $VER"
else
  fail "Version output looks wrong: $VER"
  exit 1
fi

# -----------------------------------------------------------------------
# Policy validation (JSON output)
# -----------------------------------------------------------------------
echo ""
echo "=== Policy validation (JSON) ==="
"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output json "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/result.json" || true
ALLOWED=$(jq '.summary.allowed' "$TMPDIR_TEST/result.json")
BLOCKED=$(jq '.summary.blocked' "$TMPDIR_TEST/result.json")
echo "Allowed actions: $ALLOWED"
echo "Blocked actions: $BLOCKED"

EXPECTED_ALLOWED=6
EXPECTED_BLOCKED=3
if [ "$ALLOWED" -ne "$EXPECTED_ALLOWED" ]; then
  fail "Expected $EXPECTED_ALLOWED allowed actions, got $ALLOWED"
else
  pass "Allowed count correct ($ALLOWED)"
fi
if [ "$BLOCKED" -ne "$EXPECTED_BLOCKED" ]; then
  fail "Expected $EXPECTED_BLOCKED blocked actions, got $BLOCKED"
else
  pass "Blocked count correct ($BLOCKED)"
fi

# -----------------------------------------------------------------------
# Table output format
# -----------------------------------------------------------------------
echo ""
echo "=== Table output format ==="
"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output table "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/table_out.txt" || true
grep -q "ALLOWED" "$TMPDIR_TEST/table_out.txt" \
  && pass "Table output has ALLOWED column" \
  || fail "Table output missing ALLOWED column"
grep -q "BLOCKED" "$TMPDIR_TEST/table_out.txt" \
  && pass "Table output has BLOCKED column" \
  || fail "Table output missing BLOCKED column"
grep -q "ec2:DescribeInstances" "$TMPDIR_TEST/table_out.txt" \
  && pass "Table has expected action" \
  || fail "Table missing expected action"

# -----------------------------------------------------------------------
# Single action check — allowed actions
# -----------------------------------------------------------------------
echo ""
echo "=== check-action — allowed ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances correctly allowed" \
  || fail "ec2:DescribeInstances should be allowed"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" s3:GetObject \
  && pass "s3:GetObject correctly allowed" \
  || fail "s3:GetObject should be allowed"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" iam:GetUser \
  && pass "iam:GetUser correctly allowed" \
  || fail "iam:GetUser should be allowed"

# -----------------------------------------------------------------------
# Single action check — blocked actions
# -----------------------------------------------------------------------
echo ""
echo "=== check-action — blocked ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" ec2:RunInstances \
  && fail "ec2:RunInstances should be blocked" \
  || pass "ec2:RunInstances correctly blocked"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" iam:CreateRole \
  && fail "iam:CreateRole should be blocked" \
  || pass "iam:CreateRole correctly blocked"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" s3:PutObject \
  && fail "s3:PutObject should be blocked" \
  || pass "s3:PutObject correctly blocked"

# -----------------------------------------------------------------------
# Simple pattern matching
# -----------------------------------------------------------------------
echo ""
echo "=== Simple pattern matching ==="
"$BINARY" check-action --pb "$TESTDATA/patterns.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances matches ec2:Describe*" \
  || fail "Pattern ec2:Describe* should match ec2:DescribeInstances"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" ec2:DescribeSecurityGroups \
  && pass "ec2:DescribeSecurityGroups matches ec2:Describe*" \
  || fail "Pattern ec2:Describe* should match ec2:DescribeSecurityGroups"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" s3:GetObject \
  && pass "s3:GetObject matches s3:Get*" \
  || fail "Pattern s3:Get* should match s3:GetObject"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" kinesis:PutRecord \
  && pass "kinesis:PutRecord matches kinesis:*co*" \
  || fail "Pattern kinesis:*co* should match kinesis:PutRecord"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" ec2:RunInstances \
  && fail "ec2:RunInstances should not match any pattern" \
  || pass "ec2:RunInstances correctly rejected"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" s3:PutObject \
  && fail "s3:PutObject should not match s3:Get*" \
  || pass "s3:PutObject correctly rejected"

# -----------------------------------------------------------------------
# Multi-action check-action
# -----------------------------------------------------------------------
echo ""
echo "=== Multi-action check ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" \
  ec2:DescribeInstances s3:GetObject s3:ListBucket iam:GetUser \
  && pass "All four actions correctly allowed in one invocation" \
  || fail "All four actions should be allowed"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" \
  ec2:DescribeInstances ec2:RunInstances s3:GetObject \
  && fail "Should exit non-zero because ec2:RunInstances is blocked" \
  || pass "Correctly exited non-zero when at least one action is blocked"

"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output json "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/multi_json.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 3' "$TMPDIR_TEST/multi_json.json" > /dev/null \
  && pass "JSON summary counts correct" \
  || fail "JSON summary counts wrong"

# -----------------------------------------------------------------------
# stdin support
# -----------------------------------------------------------------------
echo ""
echo "=== stdin support ==="
cat "$TESTDATA/test-pb.json" \
  | "$BINARY" check-action --pb - ec2:DescribeInstances \
  && pass "--pb - (stdin) works for allowed action" \
  || fail "--pb - should work with stdin boundary"

cat "$TESTDATA/test-pb.json" \
  | "$BINARY" check-action --pb - ec2:RunInstances \
  && fail "ec2:RunInstances should still be blocked via stdin boundary" \
  || pass "--pb - correctly blocks action via stdin"

cat "$TESTDATA/test-policy.json" \
  | "$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output json - > "$TMPDIR_TEST/stdin_policy.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 3' "$TMPDIR_TEST/stdin_policy.json" > /dev/null \
  && pass "Policy file via stdin produces correct counts" \
  || fail "stdin policy file produced wrong counts"

# -----------------------------------------------------------------------
# NotAction in source policy
# -----------------------------------------------------------------------
echo ""
echo "=== NotAction source policy ==="
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-notaction-policy.json" > "$TMPDIR_TEST/notaction_result.json" || true

COUNT=$(jq '.summary.not_action_statements' "$TMPDIR_TEST/notaction_result.json")
if [ "$COUNT" -lt "1" ]; then
  fail "Expected at least 1 not_action_statements entry, got $COUNT"
else
  pass "NotAction statement correctly surfaced: $COUNT entry/entries"
fi

jq -e '.warnings | length > 0' "$TMPDIR_TEST/notaction_result.json" > /dev/null \
  && pass "Warnings array is non-empty" \
  || fail "Warnings array is empty, expected NotAction warning"

jq -r '.warnings[]' "$TMPDIR_TEST/notaction_result.json" | grep -qi "notaction" \
  && pass "NotAction mentioned in warnings" \
  || fail "NotAction not mentioned in warnings"

jq -e '.summary.skipped_deny == 1' "$TMPDIR_TEST/notaction_result.json" \
  && pass "Deny action correctly skipped" \
  || fail "Expected 1 skipped_deny"

"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  "$TESTDATA/test-notaction-policy.json" 2>&1 | tee "$TMPDIR_TEST/notaction_list.txt" || true

grep -qi "notaction\|manual review" "$TMPDIR_TEST/notaction_list.txt" \
  && pass "List output flags NotAction statements for manual review" \
  || fail "NotAction manual review note missing from list output"

# -----------------------------------------------------------------------
# Wildcard actions in source policy
# -----------------------------------------------------------------------
echo ""
echo "=== Wildcard source policy ==="
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-wildcard-policy.json" > "$TMPDIR_TEST/wildcard_result.json" || true

jq -r '.warnings[]' "$TMPDIR_TEST/wildcard_result.json" | grep -qi "wildcard" \
  && pass "Wildcard warning present" \
  || fail "Wildcard warning missing"

W_ALLOWED=$(jq '.summary.allowed' "$TMPDIR_TEST/wildcard_result.json")
W_BLOCKED=$(jq '.summary.blocked' "$TMPDIR_TEST/wildcard_result.json")
echo "Wildcard policy: allowed=$W_ALLOWED blocked=$W_BLOCKED"

if [ "$W_ALLOWED" -ne "2" ]; then
  fail "Expected 2 allowed, got $W_ALLOWED"
else
  pass "Wildcard allowed count correct ($W_ALLOWED)"
fi
if [ "$W_BLOCKED" -ne "2" ]; then
  fail "Expected 2 blocked, got $W_BLOCKED"
else
  pass "Wildcard blocked count correct ($W_BLOCKED)"
fi

# -----------------------------------------------------------------------
# Condition and NotResource warnings
# -----------------------------------------------------------------------
echo ""
echo "=== Condition and NotResource warnings ==="
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-conditions-policy.json" > "$TMPDIR_TEST/conditions_result.json" || true

WARNINGS=$(jq '[.warnings[] | ascii_downcase]' "$TMPDIR_TEST/conditions_result.json")

echo "$WARNINGS" | grep -q "condition" \
  && pass "Condition warning present" \
  || fail "Condition warning missing"

echo "$WARNINGS" | grep -q "notresource" \
  && pass "NotResource warning present" \
  || fail "NotResource warning missing"

# -----------------------------------------------------------------------
# --policy-file flag (multi-policy merging)
# -----------------------------------------------------------------------
echo ""
echo "=== --policy-file flag ==="

# Single --policy-file (same as positional arg)
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --policy-file "$TESTDATA/test-policy.json" \
  --output json > "$TMPDIR_TEST/pf_single.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 3' "$TMPDIR_TEST/pf_single.json" > /dev/null \
  && pass "--policy-file works as sole policy source" \
  || fail "--policy-file sole source counts wrong"

# --policy-file combined with positional arg (actions merged, deduplicated)
# test-policy.json:  ec2:DescribeInstances, ec2:DescribeSecurityGroups, ec2:CreateTags,
#                    ec2:RunInstances, s3:GetObject, s3:PutObject, s3:ListBucket,
#                    iam:GetUser, iam:CreateRole  (6 allowed, 3 blocked)
# test-extra-policy.json: s3:GetObject, s3:ListBucket (overlap),
#                         logs:DescribeLogGroups, logs:CreateLogStream (new, both blocked)
# Merged: original 9 + 2 new = 11 unique. Allowed: 6, Blocked: 3+2=5
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --policy-file "$TESTDATA/test-extra-policy.json" \
  --output json \
  "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/pf_merged.json" || true
MERGED_ALLOWED=$(jq '.summary.allowed' "$TMPDIR_TEST/pf_merged.json")
MERGED_BLOCKED=$(jq '.summary.blocked' "$TMPDIR_TEST/pf_merged.json")
if [ "$MERGED_ALLOWED" -eq 6 ] && [ "$MERGED_BLOCKED" -eq 5 ]; then
  pass "Merged policy counts correct (allowed=$MERGED_ALLOWED blocked=$MERGED_BLOCKED)"
else
  fail "Merged policy counts wrong (expected 6 allowed, 5 blocked; got allowed=$MERGED_ALLOWED blocked=$MERGED_BLOCKED)"
fi

# Verify deduplication — overlapping actions appear only once
jq '[.allowed[], .blocked[]]' "$TMPDIR_TEST/pf_merged.json" | sort | uniq -d > "$TMPDIR_TEST/pf_dups.txt"
if [ ! -s "$TMPDIR_TEST/pf_dups.txt" ]; then
  pass "No duplicate actions in merged output"
else
  fail "Found duplicate actions in merged output"
fi

# Two --policy-file flags (no positional arg)
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --policy-file "$TESTDATA/test-policy.json" \
  --policy-file "$TESTDATA/test-extra-policy.json" \
  --output json > "$TMPDIR_TEST/pf_two.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 5' "$TMPDIR_TEST/pf_two.json" > /dev/null \
  && pass "Two --policy-file flags merged correctly" \
  || fail "Two --policy-file merge counts wrong"

# No policy source at all → should error
"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" 2>"$TMPDIR_TEST/no_source_err.txt" \
  && fail "Should error when no policy source specified" \
  || true
grep -qi "at least one" "$TMPDIR_TEST/no_source_err.txt" \
  && pass "Errors when no policy source specified" \
  || fail "Should error when no policy source specified"

# -----------------------------------------------------------------------
# diff subcommand
# -----------------------------------------------------------------------
echo ""
echo "=== diff subcommand ==="
"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  --output json \
  "$TESTDATA/test-diff-policy.json" > "$TMPDIR_TEST/diff_result.json" || true

GAINED=$(jq '.summary.gained' "$TMPDIR_TEST/diff_result.json")
LOST=$(jq '.summary.lost' "$TMPDIR_TEST/diff_result.json")
UNCHANGED=$(jq '.summary.unchanged' "$TMPDIR_TEST/diff_result.json")

if [ "$GAINED" -ne "2" ]; then
  fail "Expected 2 gained, got $GAINED"
else
  pass "Diff gained count correct ($GAINED)"
fi
if [ "$LOST" -ne "2" ]; then
  fail "Expected 2 lost, got $LOST"
else
  pass "Diff lost count correct ($LOST)"
fi
if [ "$UNCHANGED" -ne "4" ]; then
  fail "Expected 4 unchanged, got $UNCHANGED"
else
  pass "Diff unchanged count correct ($UNCHANGED)"
fi

jq -e '[.gained[]] | contains(["ec2:RunInstances","logs:CreateLogGroup"])' "$TMPDIR_TEST/diff_result.json" \
  && pass "gained list contains expected actions" \
  || fail "gained list wrong: $(jq '.gained' "$TMPDIR_TEST/diff_result.json")"

jq -e '[.lost[]] | contains(["iam:GetUser","s3:PutObject"])' "$TMPDIR_TEST/diff_result.json" \
  && pass "lost list contains expected actions" \
  || fail "lost list wrong: $(jq '.lost' "$TMPDIR_TEST/diff_result.json")"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  "$TESTDATA/test-diff-policy.json" \
  && fail "diff should exit non-zero because access is lost" \
  || pass "diff correctly exits non-zero when access is lost"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-old-pb.json" \
  "$TESTDATA/test-diff-policy.json" \
  && pass "diff exits zero when boundaries are identical (nothing lost)" \
  || fail "diff should exit zero when boundaries are identical"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  "$TESTDATA/test-diff-policy.json" > "$TMPDIR_TEST/diff_list.txt" || true

grep -q "gained\|Newly allowed" "$TMPDIR_TEST/diff_list.txt" \
  && pass "diff list output mentions gained actions" \
  || fail "diff list output missing gained section"

grep -q "lost\|No longer allowed" "$TMPDIR_TEST/diff_list.txt" \
  && pass "diff list output mentions lost actions" \
  || fail "diff list output missing lost section"

"$BINARY" diff --pb "$TESTDATA/test-diff-old-pb.json" "$TESTDATA/test-diff-policy.json" \
  && fail "Should error when --pb-new is missing" \
  || pass "Correctly errors when --pb-new is missing"

# -----------------------------------------------------------------------
# --version flag
# -----------------------------------------------------------------------
echo ""
echo "=== --version flag ==="
"$BINARY" --version \
  && pass "--version flag works" \
  || fail "--version flag failed"

"$BINARY" --version | grep -qE "iam-pb-check|version" \
  && pass "Version output looks correct" \
  || fail "Version output missing expected text"

# -----------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------
echo ""
echo "=== Edge cases ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" EC2:DESCRIBEINSTANCES \
  && pass "Uppercase action correctly matched (case-insensitive)" \
  || fail "Action matching should be case-insensitive"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" EC2:DESCRIBEINSTANCES \
  && pass "Pattern matching is case-insensitive" \
  || fail "Pattern matching should be case-insensitive"

# JSON output has no null arrays
cat > "$TMPDIR_TEST/fully-allowed-policy.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
EOF
"$BINARY" check-policy \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --output json \
  "$TMPDIR_TEST/fully-allowed-policy.json" > "$TMPDIR_TEST/no_blocked.json"

jq -e '.blocked | type == "array"' "$TMPDIR_TEST/no_blocked.json" \
  && pass "blocked is [] not null" \
  || fail "blocked should be array, not null"

jq -e '.skipped_deny | type == "array"' "$TMPDIR_TEST/no_blocked.json" \
  && pass "skipped_deny is [] not null" \
  || fail "skipped_deny should be array, not null"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" totally:FakeAction \
  && fail "Unknown action should be blocked (not in boundary)" \
  || pass "Unknown action correctly blocked"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
# Go unit tests
# -----------------------------------------------------------------------
echo ""
echo "Running Go unit tests..."
if go test ./... 2>&1; then
  pass "Go unit tests"
else
  fail "Go unit tests"
fi

# -----------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Tests passed: $PASSED"
echo "  Tests failed: $FAILED"
echo "========================================"

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
