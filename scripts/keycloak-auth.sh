#!/bin/bash

# Keycloak JWT Generation Script for Cashu Wallet Enclave
# This script authenticates users and generates JWT tokens

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-cashu-enclave}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-cashu-wallet-cli}"
CREDENTIALS_FILE="${CASHU_CREDENTIALS_FILE:-$HOME/.cashu-wallet-enclave}"
KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-cashu-enclave-wallet-keycloak-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Flags
JWT_ONLY=false
USERNAME=""
PASSWORD=""
CREATE_USER=false

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

Generate JWT tokens for Cashu Wallet using Keycloak authentication.

Options:
  -u, --username USERNAME    Username (prompts if not provided)
  -p, --password PASSWORD    Password (prompts if not provided)
  -c, --create              Create user if it doesn't exist
  -j, --jwt-only            Output only the JWT token (for scripting)
  -h, --help                Show this help message

Environment Variables:
  KEYCLOAK_URL              Keycloak server URL (default: http://localhost:8080)
  KEYCLOAK_REALM            Keycloak realm name (default: cashu-enclave)
  KEYCLOAK_CLIENT_ID        Client ID (default: cashu-wallet-cli)
  CASHU_CREDENTIALS_FILE    Credentials file path (default: ~/.cashu-wallet-enclave)
  KEYCLOAK_CONTAINER        Docker container name (default: cashu-enclave-wallet-keycloak-1)

Examples:
  # Interactive mode
  $0

  # With arguments
  $0 --username alice --password secret123

  # Create user if needed
  $0 --username alice --password secret123 --create

  # For scripting (outputs only JWT)
  $0 -u alice -p secret123 --jwt-only

  # Save JWT to variable
  JWT=\$($0 -u alice -p secret123 -j)
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--username)
            USERNAME="$2"
            shift 2
            ;;
        -p|--password)
            PASSWORD="$2"
            shift 2
            ;;
        -c|--create)
            CREATE_USER=true
            shift
            ;;
        -j|--jwt-only)
            JWT_ONLY=true
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

# Prompt for username if not provided
if [ -z "$USERNAME" ]; then
    read -p "Username: " USERNAME
fi

# Prompt for password if not provided
if [ -z "$PASSWORD" ]; then
    read -sp "Password: " PASSWORD
    echo
fi

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    print_error "Username and password are required"
    exit 1
fi

# Check if Keycloak is accessible
if ! curl -sf "$KEYCLOAK_URL/realms/$REALM" > /dev/null 2>&1; then
    print_error "Keycloak is not accessible at $KEYCLOAK_URL"
    print_info "Make sure docker-compose is running: docker compose up"
    exit 1
fi

# Try to authenticate first
print_info "Attempting to authenticate as '$USERNAME'..."
AUTH_RESPONSE=$(curl -s -X POST \
    "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$USERNAME" \
    -d "password=$PASSWORD" \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID")

# Check if authentication succeeded
if echo "$AUTH_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    print_success "Authentication successful"
    TOKEN_RESPONSE="$AUTH_RESPONSE"
else
    # Authentication failed
    AUTH_ERROR=$(echo "$AUTH_RESPONSE" | jq -r '.error_description // .error // "Unknown error"')
    print_info "Authentication failed: $AUTH_ERROR"
    
    if [ "$CREATE_USER" = false ]; then
        print_error "User does not exist or password is incorrect"
        print_info "Use --create flag to create the user automatically"
        exit 1
    fi
    
    # Check if docker is available for user creation
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required for user creation but not installed"
        exit 1
    fi
    
    # Check if Keycloak container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${KEYCLOAK_CONTAINER}$"; then
        print_error "Keycloak container '${KEYCLOAK_CONTAINER}' is not running"
        print_info "Start services with: docker compose up"
        exit 1
    fi
    
    print_info "Creating/updating user..."
    
    # Login to kcadm
    if ! docker exec "$KEYCLOAK_CONTAINER" /opt/keycloak/bin/kcadm.sh config credentials \
        --server http://localhost:8080 \
        --realm master \
        --user admin \
        --password admin > /dev/null 2>&1; then
        print_error "Failed to authenticate as Keycloak admin"
        exit 1
    fi
    
    # Check if user exists
    USER_ID=$(docker exec "$KEYCLOAK_CONTAINER" /opt/keycloak/bin/kcadm.sh get users \
        -r "$REALM" \
        -q "username=$USERNAME" \
        -q "exact=true" 2>/dev/null | jq -r '.[0].id // empty')
    
    if [ -z "$USER_ID" ]; then
        # Create new user
        print_info "Creating new user '$USERNAME'..."
        if ! docker exec "$KEYCLOAK_CONTAINER" /opt/keycloak/bin/kcadm.sh create users \
            -r "$REALM" \
            -s username="$USERNAME" \
            -s enabled=true \
            -s emailVerified=true \
            -s firstName="$USERNAME" \
            -s lastName="User" \
            -s email="$USERNAME@local.dev" \
            -s 'requiredActions=[]' > /dev/null 2>&1; then
            print_error "Failed to create user"
            exit 1
        fi
        print_success "User created successfully"
        
        # Get the newly created user ID
        USER_ID=$(docker exec "$KEYCLOAK_CONTAINER" /opt/keycloak/bin/kcadm.sh get users \
            -r "$REALM" \
            -q "username=$USERNAME" \
            -q "exact=true" 2>/dev/null | jq -r '.[0].id')
    else
        print_info "User already exists, updating password..."
    fi
    
    # Set password
    if ! docker exec "$KEYCLOAK_CONTAINER" /opt/keycloak/bin/kcadm.sh set-password \
        -r "$REALM" \
        --username "$USERNAME" \
        --new-password "$PASSWORD" > /dev/null 2>&1; then
        print_error "Failed to set password"
        exit 1
    fi
    print_success "Password updated successfully"
    
    # Wait for changes to propagate
    sleep 2
    
    # Now authenticate with the new/updated credentials
    print_info "Authenticating with new credentials..."
    TOKEN_RESPONSE=$(curl -s -X POST \
        "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$USERNAME" \
        -d "password=$PASSWORD" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID")
    
    if ! echo "$TOKEN_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
        print_error "Failed to authenticate after user setup"
        AUTH_ERROR=$(echo "$TOKEN_RESPONSE" | jq -r '.error_description // .error // "Unknown error"')
        print_error "Error: $AUTH_ERROR"
        exit 1
    fi
    print_success "Authentication successful"
fi

# Extract tokens
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')
REFRESH_EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_expires_in')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    print_error "Failed to obtain access token"
    exit 1
fi

# If JWT-only mode, just print the token and exit
if [ "$JWT_ONLY" = true ]; then
    echo "$ACCESS_TOKEN"
    exit 0
fi

# Calculate expiry timestamps
CURRENT_TIME=$(date +%s)
ACCESS_EXPIRY=$((CURRENT_TIME + EXPIRES_IN))
REFRESH_EXPIRY=$((CURRENT_TIME + REFRESH_EXPIRES_IN))

# Save credentials to file
CREDENTIALS_DATA=$(cat <<EOF
{
    "keycloak_url": "$KEYCLOAK_URL",
    "realm": "$REALM",
    "client_id": "$CLIENT_ID",
    "username": "$USERNAME",
    "access_token": "$ACCESS_TOKEN",
    "refresh_token": "$REFRESH_TOKEN",
    "access_expiry": $ACCESS_EXPIRY,
    "refresh_expiry": $REFRESH_EXPIRY,
    "updated_at": "$(date -Iseconds)"
}
EOF
)

echo "$CREDENTIALS_DATA" > "$CREDENTIALS_FILE"
chmod 600 "$CREDENTIALS_FILE"

print_success "Credentials saved to $CREDENTIALS_FILE"
print_info "Access token expires in ${EXPIRES_IN}s ($(date -d "@$ACCESS_EXPIRY" 2>/dev/null || date -r "$ACCESS_EXPIRY"))"
print_info "Refresh token expires in ${REFRESH_EXPIRES_IN}s ($(date -d "@$REFRESH_EXPIRY" 2>/dev/null || date -r "$REFRESH_EXPIRY"))"

# Display the access token (for manual use if needed)
echo
print_info "Access Token (JWT):"
echo "$ACCESS_TOKEN"