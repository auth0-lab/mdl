#!/bin/bash
#
# Usage: source azure-env.sh

# Azure KeyVault URL
# Format: https://<vault-name>.vault.azure.net
export AZURE_KEYVAULT_URL=""

# Azure Active Directory Tenant ID
# Find this in Azure Portal -> Azure Active Directory -> Properties -> Tenant ID
export AZURE_TENANT_ID=""

# Service Principal Client ID (Application ID)
# Find this in Azure Portal -> Azure Active Directory -> App registrations ->
# Your App -> Application ID
export AZURE_CLIENT_ID=""

# Service Principal Client Secret
# Generate this in Azure Portal -> Azure Active Directory -> App registrations ->
# Your App -> Certificates & secrets
export AZURE_CLIENT_SECRET=""


echo "Azure KeyVault environment variables set:"
echo "  AZURE_KEYVAULT_URL: $AZURE_KEYVAULT_URL"
echo "  AZURE_TENANT_ID:    $AZURE_TENANT_ID"
echo "  AZURE_CLIENT_ID:    $AZURE_CLIENT_ID"
echo "  AZURE_CLIENT_SECRET: ****"

# Instructions for setting up Azure Service Principal
cat <<'EOF'

To create a Service Principal with Key Vault access:

1. Create a service principal:
   az ad sp create-for-rbac --name "OpenSSL-KeyVault-Provider" \
     --skip-assignment

2. Grant Key Vault permissions:
   az keyvault set-policy --name <vault-name> \
     --spn <client-id> \
     --key-permissions get list sign verify encrypt decrypt wrapKey unwrapKey \
     --secret-permissions get list \
     --certificate-permissions get list

3. Copy the output values to this file:
   - appId -> AZURE_CLIENT_ID
   - password -> AZURE_CLIENT_SECRET
   - tenant -> AZURE_TENANT_ID

4. Set your vault URL:
   - AZURE_KEYVAULT_URL (format: https://<vault-name>.vault.azure.net)

For more information:
https://docs.microsoft.com/en-us/azure/key-vault/general/authentication

EOF
