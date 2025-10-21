#!/bin/bash
set -e

echo "Waiting for Keycloak to be ready..."
for i in {1..60}; do
  if timeout 2 bash -c "exec 3<>/dev/tcp/keycloak/8080 && echo -e 'GET /realms/master HTTP/1.1\r\nHost: keycloak\r\nConnection: close\r\n\r\n' >&3 && grep -q 'HTTP/1.1 200' <&3" 2>/dev/null; then
    echo "Keycloak is ready"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "ERROR: Keycloak did not become ready in time"
    exit 1
  fi
  sleep 2
done

# Wait a bit more for admin API to be ready
sleep 5

echo "Logging in to Keycloak admin..."
if ! /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://keycloak:8080 \
  --realm master \
  --user admin \
  --password admin 2>/dev/null; then
  echo "ERROR: Failed to authenticate as Keycloak admin"
  exit 1
fi
echo "Successfully logged in to Keycloak admin"

# Check if realm already exists
echo "Checking if cashu-enclave realm exists..."
if /opt/keycloak/bin/kcadm.sh get realms/cashu-enclave > /dev/null 2>&1; then
  echo "cashu-enclave realm already exists - skipping creation"
else
  echo "Creating cashu-enclave realm..."
  
  # Create realm with all settings at once
  /opt/keycloak/bin/kcadm.sh create realms \
    -s realm=cashu-enclave \
    -s enabled=true \
    -s sslRequired=none \
    -s registrationAllowed=true \
    -s loginWithEmailAllowed=true \
    -s duplicateEmailsAllowed=false \
    -s resetPasswordAllowed=true \
    -s editUsernameAllowed=false \
    -s bruteForceProtected=true \
    -s verifyEmail=false \
    -s registrationEmailAsUsername=false
  
  echo "cashu-enclave realm created successfully"
  
  # Create the client
  echo "Creating cashu-wallet-cli client..."
  /opt/keycloak/bin/kcadm.sh create clients -r cashu-enclave \
    -s clientId=cashu-wallet-cli \
    -s enabled=true \
    -s publicClient=true \
    -s directAccessGrantsEnabled=true \
    -s standardFlowEnabled=false \
    -s implicitFlowEnabled=false \
    -s serviceAccountsEnabled=false \
    -s protocol=openid-connect \
    -s 'attributes={"access.token.lifespan":"3600"}'
  
  echo "cashu-wallet-cli client created successfully"
  
  # Disable OTP requirement in direct grant flow
  echo "Configuring direct grant flow..."
  FLOW_EXECUTIONS=$(/opt/keycloak/bin/kcadm.sh get authentication/flows/direct%20grant/executions -r cashu-enclave 2>/dev/null)
  CONDITIONAL_OTP_ID=$(echo "$FLOW_EXECUTIONS" | grep -A5 '"displayName" : "Direct Grant - Conditional OTP"' | grep '"id"' | sed 's/.*"id" : "\(.*\)".*/\1/' | head -1)
  
  if [ -n "$CONDITIONAL_OTP_ID" ]; then
    /opt/keycloak/bin/kcadm.sh update authentication/flows/direct%20grant/executions -r cashu-enclave \
      -b "{\"id\": \"$CONDITIONAL_OTP_ID\", \"requirement\": \"DISABLED\"}" 2>/dev/null || true
    echo "Disabled OTP requirement in direct grant flow"
  fi
fi

echo "Keycloak initialization complete"