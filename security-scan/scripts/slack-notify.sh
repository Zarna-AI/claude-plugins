#!/bin/bash
# slack-notify.sh - Send security scan notification to Slack
# Usage: ./slack-notify.sh <webhook_url|env> <report_path>
#
# If webhook_url is "env", uses SECURITY_SLACK_WEBHOOK environment variable

set -e

WEBHOOK_URL="$1"
REPORT_PATH="$2"

if [[ "$WEBHOOK_URL" == "env" ]]; then
    WEBHOOK_URL="${SECURITY_SLACK_WEBHOOK}"
fi

if [[ -z "$WEBHOOK_URL" ]]; then
    echo "Error: No Slack webhook URL provided"
    exit 1
fi

if [[ ! -f "$REPORT_PATH" ]]; then
    echo "Error: Report file not found: $REPORT_PATH"
    exit 1
fi

# Extract counts from report
CRITICAL=$(grep -cE "Critical.*[0-9]+|### \[CRITICAL\]" "$REPORT_PATH" 2>/dev/null | head -1 || echo "0")
HIGH=$(grep -cE "High.*[0-9]+|### \[HIGH\]" "$REPORT_PATH" 2>/dev/null | head -1 || echo "0")
MEDIUM=$(grep -cE "Medium.*[0-9]+|### \[MEDIUM\]" "$REPORT_PATH" 2>/dev/null | head -1 || echo "0")
LOW=$(grep -cE "Low.*[0-9]+|### \[LOW\]" "$REPORT_PATH" 2>/dev/null | head -1 || echo "0")

# Determine status
if [[ "$CRITICAL" -gt 0 ]]; then
    EMOJI=":rotating_light:"
    STATUS="CRITICAL issues found"
elif [[ "$HIGH" -gt 0 ]]; then
    EMOJI=":warning:"
    STATUS="High severity issues found"
else
    EMOJI=":white_check_mark:"
    STATUS="Review complete"
fi

# Build message
MESSAGE="{
  \"blocks\": [
    {\"type\": \"header\", \"text\": {\"type\": \"plain_text\", \"text\": \"${EMOJI} Security Scan Report\"}},
    {\"type\": \"section\", \"text\": {\"type\": \"mrkdwn\", \"text\": \"*Findings:* Critical: ${CRITICAL} | High: ${HIGH} | Medium: ${MEDIUM} | Low: ${LOW}\"}},
    {\"type\": \"section\", \"text\": {\"type\": \"mrkdwn\", \"text\": \"*Status:* ${STATUS}\"}},
    {\"type\": \"context\", \"elements\": [{\"type\": \"mrkdwn\", \"text\": \"Report: \`${REPORT_PATH}\`\"}]}
  ]
}"

curl -s -X POST -H 'Content-type: application/json' --data "$MESSAGE" "$WEBHOOK_URL"
echo "Notification sent"
