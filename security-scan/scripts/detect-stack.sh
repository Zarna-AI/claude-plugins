#!/bin/bash
# detect-stack.sh - Auto-detect technology stack in a codebase
# Usage: ./detect-stack.sh [directory]
# Output: JSON array of detected technologies

DIR="${1:-.}"
DETECTED=()

# Helper function to add to detected list
add_detected() {
    local tech="$1"
    for item in "${DETECTED[@]}"; do
        if [[ "$item" == "$tech" ]]; then
            return
        fi
    done
    DETECTED+=("$tech")
}

# Check for package.json (Node.js ecosystem)
PKG_FILES=$(find "$DIR" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null)
for PKG_FILE in $PKG_FILES; do
    if grep -q '"next"' "$PKG_FILE" 2>/dev/null; then
        add_detected "nextjs"
    fi
    if grep -q '"react"' "$PKG_FILE" 2>/dev/null && ! grep -q '"next"' "$PKG_FILE" 2>/dev/null; then
        add_detected "react"
    fi
    if grep -q '"vue"' "$PKG_FILE" 2>/dev/null; then
        add_detected "vuejs"
    fi
    if grep -q '"@angular/core"' "$PKG_FILE" 2>/dev/null; then
        add_detected "angular"
    fi
    if grep -q '"express"' "$PKG_FILE" 2>/dev/null; then
        add_detected "express"
    fi
    if grep -q '"@supabase/supabase-js"' "$PKG_FILE" 2>/dev/null; then
        add_detected "supabase"
    fi
done

# Check for Python requirements
REQ_FILES=$(find "$DIR" -name "requirements.txt" -not -path "*/venv/*" -not -path "*/.venv/*" 2>/dev/null)
for REQ_FILE in $REQ_FILES; do
    if grep -qi "fastapi" "$REQ_FILE" 2>/dev/null; then
        add_detected "fastapi"
    fi
    if grep -qi "django" "$REQ_FILE" 2>/dev/null; then
        add_detected "django"
    fi
    if grep -qi "flask" "$REQ_FILE" 2>/dev/null; then
        add_detected "flask"
    fi
    if grep -qi "supabase" "$REQ_FILE" 2>/dev/null; then
        add_detected "supabase"
    fi
    if grep -qi "qdrant" "$REQ_FILE" 2>/dev/null; then
        add_detected "qdrant"
    fi
done

# Check for environment files indicating services
ENV_FILES=$(find "$DIR" -name ".env*" -not -name ".env.example" 2>/dev/null | head -5)
for env_file in $ENV_FILES; do
    if grep -qi "SUPABASE" "$env_file" 2>/dev/null; then
        add_detected "supabase"
    fi
    if grep -qi "QDRANT" "$env_file" 2>/dev/null; then
        add_detected "qdrant"
    fi
    if grep -qi "FIREBASE" "$env_file" 2>/dev/null; then
        add_detected "firebase"
    fi
    if grep -qi "MONGODB\|MONGO_URI" "$env_file" 2>/dev/null; then
        add_detected "mongodb"
    fi
    if grep -qi "REDIS" "$env_file" 2>/dev/null; then
        add_detected "redis"
    fi
done

# Output as JSON array
if [[ ${#DETECTED[@]} -eq 0 ]]; then
    echo "[]"
else
    printf '['
    first=true
    for tech in "${DETECTED[@]}"; do
        if $first; then
            first=false
        else
            printf ','
        fi
        printf '"%s"' "$tech"
    done
    printf ']\n'
fi
