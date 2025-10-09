#!/bin/bash
set -e

echo "Waiting for Keycloak to be ready..."
for i in {1..120}; do
  if timeout 2 bash -c "exec 3<>/dev/tcp/keycloak/8080 && echo -e 'GET /realms/master HTTP/1.1\r\nHost: keycloak\r\nConnection: close\r\n\r\n' >&3 && grep -q 'HTTP/1.1 200' <&3" 2>/dev/null; then
    echo "Keycloak is ready"
    break
  fi
  echo "Waiting for Keycloak... ($i/120)"
  sleep 2
done

# Additional wait to ensure admin API is ready
sleep 10

echo "Logging in to Keycloak admin..."
for i in {1..10}; do
  if /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://keycloak:8080 \
    --realm master \
    --user admin \
    --password admin 2>/dev/null; then
    echo "Successfully logged in to Keycloak admin"
    break
  fi
  echo "Retrying admin login... ($i/10)"
  sleep 3
done

echo "Checking if cashu-enclave realm exists..."
if /opt/keycloak/bin/kcadm.sh get realms/cashu-enclave > /dev/null 2>&1; then
  echo "cashu-enclave realm already exists"

  # Update realm to skip required actions for direct grant
  echo "Configuring realm settings..."
  /opt/keycloak/bin/kcadm.sh update realms/cashu-enclave \
    -s verifyEmail=false \
    -s registrationEmailAsUsername=false

  # Disable OTP conditional in direct grant flow
  echo "Configuring direct grant flow..."
  FLOW_EXECUTIONS=$(/opt/keycloak/bin/kcadm.sh get authentication/flows/direct%20grant/executions -r cashu-enclave 2>/dev/null)
  CONDITIONAL_OTP_ID=$(echo "$FLOW_EXECUTIONS" | grep -A5 '"displayName" : "Direct Grant - Conditional OTP"' | grep '"id"' | sed 's/.*"id" : "\(.*\)".*/\1/' | head -1)

  if [ -n "$CONDITIONAL_OTP_ID" ]; then
    /opt/keycloak/bin/kcadm.sh update authentication/flows/direct%20grant/executions -r cashu-enclave \
      -b "{\"id\": \"$CONDITIONAL_OTP_ID\", \"requirement\": \"DISABLED\"}" 2>/dev/null || true
    echo "Disabled OTP requirement in direct grant flow"
  fi

  # Check if client exists
  echo "Checking if cashu-wallet-cli client exists..."
  if /opt/keycloak/bin/kcadm.sh get clients -r cashu-enclave --fields clientId | grep -q "cashu-wallet-cli"; then
    echo "cashu-wallet-cli client already exists"
  else
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
  fi
else
  echo "Creating cashu-enclave realm..."
  /opt/keycloak/bin/kcadm.sh create realms -f /tmp/cashu-realm.json
  echo "cashu-enclave realm created successfully"

  # Configure realm to skip required actions for direct grant
  echo "Configuring realm settings..."
  /opt/keycloak/bin/kcadm.sh update realms/cashu-enclave \
    -s verifyEmail=false \
    -s registrationEmailAsUsername=false

  # Disable OTP conditional in direct grant flow
  echo "Configuring direct grant flow..."
  FLOW_EXECUTIONS=$(/opt/keycloak/bin/kcadm.sh get authentication/flows/direct%20grant/executions -r cashu-enclave 2>/dev/null)
  CONDITIONAL_OTP_ID=$(echo "$FLOW_EXECUTIONS" | grep -A5 '"displayName" : "Direct Grant - Conditional OTP"' | grep '"id"' | sed 's/.*"id" : "\(.*\)".*/\1/' | head -1)

  if [ -n "$CONDITIONAL_OTP_ID" ]; then
    /opt/keycloak/bin/kcadm.sh update authentication/flows/direct%20grant/executions -r cashu-enclave \
      -b "{\"id\": \"$CONDITIONAL_OTP_ID\", \"requirement\": \"DISABLED\"}" 2>/dev/null || true
    echo "Disabled OTP requirement in direct grant flow"
  fi
fi
