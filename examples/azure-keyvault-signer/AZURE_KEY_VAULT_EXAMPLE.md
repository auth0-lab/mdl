# Azure Key Vault Signing Example

This example demonstrates how to use Azure Key Vault to sign mDL/MDOC documents using the
`AzureKeyVaultSigner`.

## Prerequisites

1. An Azure Key Vault instance
2. An EC (Elliptic Curve) key stored in Azure Key Vault (ES256, ES384, or ES512)
3. Appropriate Azure credentials configured (e.g., via Azure CLI, environment variables, or
   managed identity)

## Installation

```bash
npm install @auth0/mdl @azure/keyvault-keys @azure/identity
```

## Basic Usage

### Using Azure Key Vault for Signing

```typescript
import { Document, AzureKeyVaultSigner } from '@auth0/mdl';

// Create an Azure Key Vault signer
const signer = new AzureKeyVaultSigner({
  keyVaultUrl: 'https://my-vault.vault.azure.net',
  keyName: 'my-signing-key',
  keyVersion: 'latest', // Optional, defaults to latest
  // credential: new DefaultAzureCredential(), // Optional, uses DefaultAzureCredential
});

// Create and sign a document
const doc = new Document('org.iso.18013.5.1.mDL');

doc.addIssuerNameSpace('org.iso.18013.5.1', {
  family_name: 'Doe',
  given_name: 'John',
  birth_date: '1990-01-01',
  issue_date: '2024-01-01',
  expiry_date: '2034-01-01',
  issuing_country: 'US',
  document_number: '123456789',
});

// Sign using Azure Key Vault
const signedDoc = await doc.sign({
  signer,
  issuerCertificate: certificatePEM,  // Your issuer certificate
  alg: 'ES256',  // Must match your Azure Key Vault key algorithm
  kid: 'my-key-id',  // Optional key ID
});

console.log('Document signed successfully with Azure Key Vault!');
```

### Using Custom Azure Credentials

```typescript
import { AzureKeyVaultSigner } from '@auth0/mdl';
import { ClientSecretCredential } from '@azure/identity';

// Use specific credentials instead of DefaultAzureCredential
const credential = new ClientSecretCredential(
  'tenant-id',
  'client-id',
  'client-secret'
);

const signer = new AzureKeyVaultSigner({
  keyVaultUrl: 'https://my-vault.vault.azure.net',
  keyName: 'my-signing-key',
  credential,
});

// Use the signer as shown above
```

### Backward Compatibility - Traditional Signing

The traditional signing method with local keys continues to work:

```typescript
import { Document } from '@auth0/mdl';
import * as jose from 'jose';

const privateKeyJWK: jose.JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: '...',
  y: '...',
  d: '...',
  kid: 'key-id',
};

const doc = new Document('org.iso.18013.5.1.mDL');
// ... add namespaces ...

// Traditional signing (still supported)
const signedDoc = await doc.sign({
  issuerPrivateKey: privateKeyJWK,
  issuerCertificate: certificatePEM,
  alg: 'ES256',
});
```

## Supported Algorithms

Azure Key Vault supports the following EC signing algorithms that work with this library:

- **ES256** - ECDSA using P-256 and SHA-256 ✅ Supported
- **ES384** - ECDSA using P-384 and SHA-384 ✅ Supported
- **ES512** - ECDSA using P-521 and SHA-512 ✅ Supported
- **EdDSA** - Edwards-curve Digital Signature Algorithm ❌ **NOT supported by Azure Key Vault HSM**

**Note**: Azure Key Vault HSM does not support Ed25519 keys or the EdDSA algorithm. If you
need EdDSA, you must use local key signing with `LocalKeySigner`.

Make sure your Azure Key Vault key type matches the algorithm you're using.

## Azure Key Vault Setup

### Creating an EC Key in Azure Key Vault

Using Azure CLI:

```bash
# Create a P-256 key for ES256
az keyvault key create \
  --vault-name my-vault \
  --name my-signing-key \
  --kty EC \
  --curve P-256 \
  --ops sign verify

# Or create a P-384 key for ES384
az keyvault key create \
  --vault-name my-vault \
  --name my-signing-key \
  --kty EC \
  --curve P-384 \
  --ops sign verify
```

### Required Permissions

Your Azure identity needs the following permissions on the Key Vault:

- `keys/get` - To retrieve the public key
- `keys/sign` - To perform signing operations

Example policy assignment:

```bash
az keyvault set-policy \
  --name my-vault \
  --object-id <your-principal-id> \
  --key-permissions get sign
```

## Authentication Options

The `AzureKeyVaultSigner` uses Azure Identity's `DefaultAzureCredential` by default, which
tries multiple authentication methods in order:

1. **Environment variables** - `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`
2. **Managed Identity** - When running on Azure (App Service, Functions, VMs, etc.)
3. **Azure CLI** - When authenticated via `az login`
4. **Azure PowerShell** - When authenticated via PowerShell
5. **Visual Studio Code** - When signed in to Azure in VS Code

You can also provide a specific credential:

```typescript
import { ManagedIdentityCredential, EnvironmentCredential } from '@azure/identity';

// Use Managed Identity
const credential = new ManagedIdentityCredential();

// Or use environment variables
const credential = new EnvironmentCredential();

const signer = new AzureKeyVaultSigner({
  keyVaultUrl: 'https://my-vault.vault.azure.net',
  keyName: 'my-signing-key',
  credential,
});
```

## Error Handling

```typescript
try {
  const signedDoc = await doc.sign({
    signer,
    issuerCertificate: certificatePEM,
    alg: 'ES256',
  });
} catch (error) {
  if (error.message.includes('Azure Key Vault')) {
    console.error('Azure Key Vault error:', error);
    // Handle Azure-specific errors (permissions, network, etc.)
  } else if (error.message.includes('algorithm')) {
    console.error('Algorithm mismatch:', error);
    // Key algorithm doesn't match the requested algorithm
  } else {
    console.error('Signing error:', error);
  }
}
```

## Benefits of Azure Key Vault Signing

1. **Security** - Private keys never leave Azure Key Vault's HSM
2. **Compliance** - Meets regulatory requirements for key management (FIPS 140-2, etc.)
3. **Audit Trail** - All signing operations are logged in Azure Monitor
4. **Key Rotation** - Easily rotate keys without changing application code (use key versions)
5. **Access Control** - Fine-grained access control using Azure RBAC and Key Vault policies

## Complete Example

```typescript
import { Document, AzureKeyVaultSigner } from '@auth0/mdl';
import * as fs from 'fs';

async function signDocument() {
  // Read your issuer certificate
  const certificatePEM = fs.readFileSync('./issuer-cert.pem', 'utf-8');

  // Create Azure Key Vault signer
  const signer = new AzureKeyVaultSigner({
    keyVaultUrl: process.env.AZURE_KEYVAULT_URL!,
    keyName: process.env.AZURE_KEY_NAME!,
  });

  // Create document
  const doc = new Document('org.iso.18013.5.1.mDL');

  // Add driver's license data
  doc.addIssuerNameSpace('org.iso.18013.5.1', {
    family_name: 'Smith',
    given_name: 'Alice',
    birth_date: '1985-05-15',
    issue_date: '2024-01-15',
    expiry_date: '2034-01-15',
    issuing_country: 'US',
    issuing_authority: 'CA DMV',
    document_number: 'D1234567',
    portrait: portraitImageBytes,  // Your portrait image as Uint8Array
    driving_privileges: [
      {
        vehicle_category_code: 'C',
        issue_date: '2024-01-15',
        expiry_date: '2034-01-15',
      },
    ],
  });

  // Add device key
  doc.addDeviceKeyInfo({ deviceKey: devicePublicKeyJWK });

  // Set validity
  doc.addValidityInfo({
    signed: new Date(),
    validFrom: new Date(),
    validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
  });

  // Sign with Azure Key Vault
  const signedDoc = await doc.sign({
    signer,
    issuerCertificate: certificatePEM,
    alg: 'ES256',
  });

  // Encode to CBOR
  const encodedDoc = signedDoc.encode();

  console.log('Document signed and encoded successfully!');
  return encodedDoc;
}

signDocument().catch(console.error);
```

## Local Development vs Production

For local development, you can use Azure CLI authentication:

```bash
az login
az account set --subscription <your-subscription-id>
```

For production, use Managed Identity or service principals with appropriate Key Vault access
policies.

## See Also

- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Azure Identity SDK](https://docs.microsoft.com/en-us/javascript/api/overview/azure/
  identity-readme)
- [ISO 18013-5 mDL Standard](https://www.iso.org/standard/69084.html)
