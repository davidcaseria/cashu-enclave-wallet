#!/bin/bash

# Keycloak JWT Refresh Script for Cashu Wallet Enclave
# This script refreshes JWT tokens using the refresh token

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-cashu-enclave}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-cashu-wallet-cli}"
CREDENTIALS_FILE="${CASHU_CREDENTIALS_FILE:-$HOME/.cashu-wallet-enclave}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Flags
JWT_ONLY=false
FORCE_AUTH=false

print_success() {
    if [ "$JWT_ONLY" = false ]; then
        echo -e "${GREEN}✓ $1${NC}" >&2
    fi
}

print_error() {
    echo -e "${RED}✗ $1${NC}" >&2
}

print_info() {
    if [ "$JWT_ONLY" = false ]; then
        echo -e "${YELLOW}ℹ $1${NC}" >&2
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Refresh JWT tokens for Cashu Wallet using the stored refresh token.

Options:
  -j, --jwt-only    Output only the JWT token (for scripting)
  -f, --force       Force re-authentication even if token is still valid
  -h, --help        Show this help message

Environment Variables:
  KEYCLOAK_URL              Keycloak server URL (default: http://localhost:8080)
  KEYCLOAK_REALM            Keycloak realm name (default: cashu-enclave)
  KEYCLOAK_CLIENT_ID        Client ID (default: cashu-wallet-cli)
  CASHU_CREDENTIALS_FILE    Credentials file path (default: ~/.cashu-wallet-enclave)

Examples:
  # Refresh token if needed
  $0

  # Force refresh
  $0 --force

  # For scripting (outputs only JWT)
  $0 --jwt-only

  # Get current or refreshed JWT
  JWT=\$($0 -j)
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -j|--jwt-only)
            JWT_ONLY=true
            shift
            ;;
        -f|--force)
            FORCE_AUTH=true
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information" >&2
            exit 1
            ;;
    esac
done

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Please install jq."
    exit 1
fi

# Check if credentials file exists
if [ ! -f "$CREDENTIALS_FILE" ]; then
    print_error "No credentials found at $CREDENTIALS_FILE"
    print_info "Please run ./scripts/keycloak-auth.sh first to authenticate"
    exit 1
fi

# Load existing credentials
CREDENTIALS=$(cat "$CREDENTIALS_FILE")
USERNAME=$(echo "$CREDENTIALS" | jq -r '.username')
ACCESS_TOKEN=$(echo "$CREDENTIALS" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$CREDENTIALS" | jq -r '.refresh_token')
ACCESS_EXPIRY=$(echo "$CREDENTIALS" | jq -r '.access_expiry')
REFRESH_EXPIRY=$(echo "$CREDENTIALS" | jq -r '.refresh_expiry')

# Get current timestamp
CURRENT_TIME=$(date +%s)

# Check if access token is still valid (with 30 second buffer)
if [ "$FORCE_AUTH" = false ] && [ "$ACCESS_EXPIRY" -gt $((CURRENT_TIME + 30)) ]; then
    print_success "Access token is still valid"
    if [ "$JWT_ONLY" = true ]; then
        echo "$ACCESS_TOKEN"
    else
        REMAINING=$((ACCESS_EXPIRY - CURRENT_TIME))
        print_info "Token expires in ${REMAINING}s"
        echo
        print_info "Access Token (JWT):"
        echo "$ACCESS_TOKEN"
    fi
    exit 0
fi

# Check if refresh token is expired
if [ "$REFRESH_EXPIRY" -lt "$CURRENT_TIME" ]; then
    print_error "Refresh token has expired"
    print_info "Please run ./scripts/keycloak-auth.sh to re-authenticate"
    exit 1
fi

# Check if Keycloak is accessible
if ! curl -sf "$KEYCLOAK_URL/realms/$REALM" > /dev/null 2>&1; then
    print_error "Keycloak is not accessible at $KEYCLOAK_URL"
    print_info "Make sure docker-compose is running: docker compose up"
    exit 1
fi

# Refresh the token
print_info "Refreshing access token for '$USERNAME'..."
REFRESH_RESPONSE=$(curl -s -X POST \
    "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token" \
    -d "refresh_token=$REFRESH_TOKEN" \
    -d "client_id=$CLIENT_ID")

# Check if refresh succeeded
if ! echo "$REFRESH_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    REFRESH_ERROR=$(echo "$REFRESH_RESPONSE" | jq -r '.error_description // .error // "Unknown error"')
    print_error "Failed to refresh token: $REFRESH_ERROR"
    print_info "Please run ./scripts/keycloak-auth.sh to re-authenticate"
    exit 1
fi

print_success "Token refreshed successfully"

# Extract new tokens
NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token')
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token')
EXPIRES_IN=$(echo "$REFRESH_RESPONSE" | jq -r '.expires_in')
REFRESH_EXPIRES_IN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_expires_in')

# Calculate new expiry timestamps
NEW_ACCESS_EXPIRY=$((CURRENT_TIME + EXPIRES_IN))
NEW_REFRESH_EXPIRY=$((CURRENT_TIME + REFRESH_EXPIRES_IN))

# Update credentials file
UPDATED_CREDENTIALS=$(cat <<EOF
{
    "keycloak_url": "$KEYCLOAK_URL",
    "realm": "$REALM",
    "client_id": "$CLIENT_ID",
    "username": "$USERNAME",
    "access_token": "$NEW_ACCESS_TOKEN",
    "refresh_token": "$NEW_REFRESH_TOKEN",
    "access_expiry": $NEW_ACCESS_EXPIRY,
    "refresh_expiry": $NEW_REFRESH_EXPIRY,
    "updated_at": "$(date -Iseconds)"
}
EOF
)

echo "$UPDATED_CREDENTIALS" > "$CREDENTIALS_FILE"
chmod 600 "$CREDENTIALS_FILE"

# If JWT-only mode, just print the token and exit
if [ "$JWT_ONLY" = true ]; then
    echo "$NEW_ACCESS_TOKEN"
    exit 0
fi

print_success "Credentials updated in $CREDENTIALS_FILE"
print_info "Access token expires in ${EXPIRES_IN}s"
print_info "Refresh token expires in ${REFRESH_EXPIRES_IN}s"

# Display the new access token
echo
print_info "Access Token (JWT):"
echo "$NEW_ACCESS_TOKEN"