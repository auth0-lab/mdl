# Azure Key Vault Signer Example

This example demonstrates how to implement a custom `Signer` for the `@auth0/mdl` library using
Azure Key Vault HSM for cryptographic signing operations.

## Overview

This implementation shows how to:
- Implement the `Signer` interface from `@auth0/mdl`
- Integrate with Azure Key Vault HSM for signing operations
- Sign mDL/MDOC documents without exposing private key material
- Use Azure Identity for authentication

## Files

- `src/AzureKeyVaultSigner.ts` - Implementation of the Signer interface for Azure Key Vault
- `__tests__/azureKeyVault.tests.ts` - Example tests demonstrating usage
- `AZURE_KEY_VAULT_EXAMPLE.md` - Detailed usage examples
- `AZURE_KEY_VAULT_INTEGRATION.md` - Technical architecture documentation
- `sample-azure-env.sh` - Template for Azure environment variables

## Prerequisites

1. An Azure Key Vault instance
2. An EC (Elliptic Curve) key stored in Azure Key Vault (ES256, ES384, or ES512)
3. Appropriate Azure credentials configured

## Installation

```bash
# Install the core library
npm install @auth0/mdl

# Install Azure dependencies for this example
npm install @azure/keyvault-keys @azure/identity
```

## Quick Start

```typescript
import { Document } from '@auth0/mdl';
import { AzureKeyVaultSigner } from './path/to/AzureKeyVaultSigner';

// Create an Azure Key Vault signer
const signer = new AzureKeyVaultSigner({
  keyVaultUrl: 'https://my-vault.vault.azure.net',
  keyName: 'my-signing-key',
});

// Create and sign a document
const doc = new Document('org.iso.18013.5.1.mDL');

doc.addIssuerNameSpace('org.iso.18013.5.1', {
  family_name: 'Doe',
  given_name: 'John',
  birth_date: '1990-01-01',
  // ... other attributes
});

// Sign using Azure Key Vault
const signedDoc = await doc.sign({
  signer,
  issuerCertificate: certificatePEM,
  alg: 'ES256',
});
```

## Supported Algorithms

Azure Key Vault HSM supports the following algorithms:

- **ES256** - ECDSA using P-256 and SHA-256 ✅
- **ES384** - ECDSA using P-384 and SHA-384 ✅
- **ES512** - ECDSA using P-521 and SHA-512 ✅

**Not Supported:**
- **EdDSA** (Ed25519) ❌ - Azure Key Vault HSM does not support Ed25519 keys. Use
  `LocalKeySigner` for EdDSA.

## Running the Tests

1. Copy `sample-azure-env.sh` to `azure-env.sh`
2. Fill in your Azure Key Vault credentials
3. Source the environment file: `source azure-env.sh`
4. Run tests from the root of the repository: `npm test`

The tests will automatically skip if Azure credentials are not configured.

## Documentation

- See [AZURE_KEY_VAULT_EXAMPLE.md](./AZURE_KEY_VAULT_EXAMPLE.md) for detailed usage examples
- See [AZURE_KEY_VAULT_INTEGRATION.md](./AZURE_KEY_VAULT_INTEGRATION.md) for technical
  architecture details

## Implementing Your Own Signer

This example can be used as a template for implementing other signing backends:

1. Implement the `Signer` interface from `@auth0/mdl`:
   ```typescript
   interface Signer {
     sign(algorithm: string, data: Uint8Array): Promise<Uint8Array>;
     getPublicKey(): Promise<jose.JWK>;
     getKeyId(): string;
   }
   ```

2. Handle algorithm-specific signing logic
3. Return signatures in the correct format
4. Provide proper error handling

Other potential implementations:
- AWS KMS Signer
- Google Cloud KMS Signer
- Hardware Security Module (HSM) Signer
- Custom enterprise signing infrastructure

## Benefits of External Signing

1. **Security** - Private keys never leave the HSM/secure environment
2. **Compliance** - Meets regulatory requirements (FIPS 140-2, etc.)
3. **Audit Trail** - All operations logged in cloud provider's monitoring
4. **Key Rotation** - Easily rotate keys without changing application code
5. **Access Control** - Fine-grained permissions via cloud IAM

## License

This example follows the same license as the @auth0/mdl library (Apache-2.0).
