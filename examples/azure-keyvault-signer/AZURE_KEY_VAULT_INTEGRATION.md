# Azure Key Vault Integration for @auth0/mdl

This document describes the Azure Key Vault signing integration added to the `@auth0/mdl` library.

## Overview

This feature adds support for signing mDL/MDOC documents using private keys stored in Azure
Key Vault, without exposing the private key material to the application. This provides enhanced
security for production environments and meets compliance requirements for key management.

## Architecture

The implementation uses a **Signer abstraction layer** that allows for multiple signing backends:

```
Document.sign()
  ├─> issuerPrivateKey (traditional, backward compatible)
  └─> signer: Signer interface
        ├─> LocalKeySigner (wraps local JWK keys)
        └─> AzureKeyVaultSigner (signs via Azure Key Vault)
```

### Key Components

1. **Signer Interface** (`src/mdoc/signing/Signer.ts`)
   - Abstract interface for signing operations
   - Supports `sign()`, `getKeyId()`, and `getAlgorithm()` methods

2. **AzureKeyVaultSigner** (`examples/azure-keyvault-signer/src/AzureKeyVaultSigner.ts`)
   - Example implementation of Signer interface using Azure Key Vault
   - Uses `@azure/keyvault-keys` and `@azure/identity` SDKs
   - Automatically hashes data and maps COSE algorithms to Azure signature algorithms
   - Note: This is an example implementation, not part of the core library

3. **LocalKeySigner** (`src/mdoc/signing/LocalKeySigner.ts`)
   - Implements Signer interface for local JWK keys
   - Provides backward compatibility and testing convenience

4. **IssuerAuth.signWithSigner()** (`src/mdoc/model/IssuerAuth.ts`)
   - New static method that constructs COSE_Sign1 structure manually
   - Bypasses cose-kit's key handling to support custom signers
   - Follows RFC 8152 Section 4.4 for Sig_structure construction

5. **Document.sign() Updates** (`src/mdoc/model/Document.ts`)
   - Extended to accept optional `signer` parameter
   - Validates that either `issuerPrivateKey` OR `signer` is provided (mutually exclusive)
   - Routes to appropriate signing method based on input

## Changes Made

### New Files in Core Library

- `src/mdoc/signing/Signer.ts` - Signer interface
- `src/mdoc/signing/LocalKeySigner.ts` - Local key implementation
- `src/mdoc/signing/index.ts` - Module exports

### Example Implementation

- `examples/azure-keyvault-signer/src/AzureKeyVaultSigner.ts` - Azure Key Vault example implementation
- `examples/azure-keyvault-signer/AZURE_KEY_VAULT_EXAMPLE.md` - Usage examples and documentation
- `examples/azure-keyvault-signer/AZURE_KEY_VAULT_INTEGRATION.md` - Integration guide (this document)

### Modified Files

- `src/mdoc/model/IssuerAuth.ts`
  - Added `signWithSigner()` static method
  - Added COSE header/algorithm constants and helper functions

- `src/mdoc/model/Document.ts`
  - Modified `sign()` to accept optional `signer` parameter
  - Added validation logic for mutually exclusive parameters
  - Integrated custom signer path

- `src/index.ts`
  - Exported `Signer` interface and `LocalKeySigner` class
  - Note: `AzureKeyVaultSigner` is not exported from the main library; it's an example implementation

- `examples/azure-keyvault-signer/package.json`
  - Lists `@azure/identity` (^4.0.0) as peer dependency
  - Lists `@azure/keyvault-keys` (^4.8.0) as peer dependency
  - Note: These Azure packages are NOT dependencies of the core `@auth0/mdl` library
  - Users must install these packages separately if using the Azure Key Vault example

## Usage

### Quick Start

```typescript
import { Document } from '@auth0/mdl';
import { AzureKeyVaultSigner } from './examples/azure-keyvault-signer/src/AzureKeyVaultSigner';

const signer = new AzureKeyVaultSigner({
  keyVaultUrl: 'https://my-vault.vault.azure.net',
  keyName: 'my-signing-key',
  algorithm: 'ES256', // Required: must match your key type
});

const doc = new Document('org.iso.18013.5.1.mDL');
// ... add namespaces ...

const signedDoc = await doc.sign({
  signer,
  issuerCertificate: certificatePEM,
});
```

### Backward Compatibility

Existing code continues to work without changes:

```typescript
const signedDoc = await doc.sign({
  issuerPrivateKey: jwkPrivateKey,  // Still works!
  issuerCertificate: certificatePEM,
  alg: 'ES256',
});
```

## Security Benefits

1. **Private Key Protection** - Keys never leave Azure Key Vault's HSM
2. **Compliance** - Meets FIPS 140-2 and other regulatory requirements
3. **Audit Logging** - All signing operations logged in Azure Monitor
4. **Access Control** - Fine-grained permissions via Azure RBAC
5. **Key Rotation** - Support for key versioning and rotation

## Supported Algorithms

Azure Key Vault HSM supports the following algorithms:

- **ES256** - ECDSA using P-256 and SHA-256 ✅
- **ES384** - ECDSA using P-384 and SHA-384 ✅
- **ES512** - ECDSA using P-521 and SHA-512 ✅

**Not Supported:**
- **EdDSA** (Ed25519) ❌ - Azure Key Vault HSM does not support Ed25519 keys. Use
  `LocalKeySigner` for EdDSA.

## Technical Details

### COSE_Sign1 Structure

The `IssuerAuth.signWithSigner()` method manually constructs the COSE_Sign1 Sig_structure:

```
Sig_structure = [
  context: "Signature1",
  protected: serialized_protected_headers,
  external_aad: empty_uint8array,
  payload: mso_payload
]
```

This is CBOR-encoded and passed to the signer's `sign()` method.

### Azure Key Vault Integration

The AzureKeyVaultSigner:
1. Hashes the data using the appropriate algorithm (SHA-256, SHA-384, or SHA-512)
2. Maps COSE algorithm names to Azure signature algorithms
3. Calls `CryptographyClient.sign()` with the digest
4. Returns the signature as a `Uint8Array`

### Type Compatibility

The implementation works with the installed version of `cose-kit` (v1.7.1), which uses plain
object types for `ProtectedHeaders` and `UnprotectedHeaders` rather than classes. Helper
functions (`protectedHeadersToMap`, `unprotectedHeadersToMap`) convert these to CBOR-encodable
Maps.

## Testing

To test the Azure Key Vault integration:

1. Set up an Azure Key Vault with an EC key
2. Configure Azure credentials (CLI, environment variables, or managed identity)
3. Run the example:

```typescript
// See AZURE_KEY_VAULT_EXAMPLE.md for complete example
```

## Future Enhancements

Potential future additions:
- AWS KMS support (`AwsKmsSigner`)
- Google Cloud KMS support (`GcpKmsSigner`)
- Hardware Security Module (HSM) support
- Key rotation strategies
- Performance optimizations (key caching)

## Contributing

When contributing additional Signer implementations:

1. Implement the `Signer` interface
2. Handle algorithm mapping appropriately
3. Ensure proper error handling
4. Add comprehensive tests
5. Document usage examples

## References

- [RFC 8152 - COSE (CBOR Object Signing and Encryption)]
  (https://datatracker.ietf.org/doc/html/rfc8152)
- [ISO 18013-5 - mDL Standard](https://www.iso.org/standard/69084.html)
- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Azure Identity SDK](https://docs.microsoft.com/en-us/javascript/api/overview/azure/
  identity-readme)

## License

This feature follows the same license as the @auth0/mdl library (Apache-2.0).
