import * as jose from 'jose';
import { COSEKeyToJWK } from 'cose-kit';
import { ClientSecretCredential } from '@azure/identity';
import {
  MDoc,
  Document,
  Verifier,
  parse,
  IssuerSignedDocument,
  AzureKeyVaultSigner,
} from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE } from './config';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

// Azure Key Vault certificate chain (leaf + intermediate + root)
// Full chain for embedding in the x5chain header
const AZURE_KEY_VAULT_CERTIFICATE_CHAIN = `-----BEGIN CERTIFICATE-----
MIID1jCCA3ygAwIBAgIUddQy2FOR8KrfEaXGToyfRw+6VYkwCgYIKoZIzj0EAwIw
gYkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T
YW4gRnJhbmNpc2NvMRYwFAYDVQQKDA1NeUNvbXBhbnkgSW5jMREwDwYDVQQLDAhT
ZWN1cml0eTEiMCAGA1UEAwwZTXlDb21wYW55IEludGVybWVkaWF0ZSBDQTAeFw0y
NTEwMjcxNDIyNDJaFw0yNjEwMjcxNDIyNDJaMHAxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRYwFAYDVQQK
DA1NeUNvbXBhbnkgSW5jMRwwGgYDVQQDDBNsZWFmMS5teWNvbXBhbnkuY29tMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQWHhjGbA4ZZEZasF62pYctQ8tHX0HMDJ
Jb0QgiTaq76b+FMZWuQ/SU2wIV9K4JfjVbLWU4JuyQO+xr5tKoA+vqOCAdgwggHU
MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUF
BwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUatgdVmySrerOBDjCpM4Og9A6hHowHwYD
VR0jBBgwFoAUhYS70VQN/x4zszXTuFXnmlwuD6YwcgYDVR0RBGswaYITbGVhZjEu
bXljb21wYW55LmNvbYIXd3d3LmxlYWYxLm15Y29tcGFueS5jb22CFSoubGVhZjEu
bXljb21wYW55LmNvbYcEwKgBZIYcaHR0cHM6Ly9sZWFmMS5teWNvbXBhbnkuY29t
LzB6BgNVHR8EczBxMDOgMaAvhi1odHRwOi8vY3JsLm15Y29tcGFueS5jb20vbXlj
b21wYW55LWludC1jYS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwtYmFja3VwLm15Y29t
cGFueS5jb20vbXljb21wYW55LWludC1jYS5jcmwwZQYIKwYBBQUHAQEEWTBXMCUG
CCsGAQUFBzABhhlodHRwOi8vb2NzcC5teWNvbXBhbnkuY29tMC4GCCsGAQUFBzAC
hiJodHRwOi8vY2EubXljb21wYW55LmNvbS9pbnQtY2EuY3J0MAoGCCqGSM49BAMC
A0gAMEUCIBACN4AUAB8y360eWaX5i6dZ7VL+MOQNm/YSUcozrWYTAiEArvMCGoep
W8VOY3Z3NNLlvdJFX8WzgV4RjBClXUcNjQA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID1jCCA3ugAwIBAgIUM51uNu3ULLYO71dDQK25v/Qr/sEwCgYIKoZIzj0EAwIw
gYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T
YW4gRnJhbmNpc2NvMRYwFAYDVQQKDA1NeUNvbXBhbnkgSW5jMREwDwYDVQQLDAhT
ZWN1cml0eTEaMBgGA1UEAwwRTXlDb21wYW55IFJvb3QgQ0EwHhcNMjUxMDI3MTQy
MjQwWhcNMzAxMDI2MTQyMjQwWjCBiTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
bGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFjAUBgNVBAoMDU15Q29t
cGFueSBJbmMxETAPBgNVBAsMCFNlY3VyaXR5MSIwIAYDVQQDDBlNeUNvbXBhbnkg
SW50ZXJtZWRpYXRlIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKZ7u2UVX
i34ILZhRc6Y2xgcLLV7V7uaIdry3zWIGerJRYBl9qc5QE+c6vhUoLr3uXJ8Ypsc5
axT88I+s40HcgaOCAcUwggHBMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBSFhLvRVA3/HjOzNdO4VeeaXC4PpjAfBgNVHSMEGDAW
gBQIYDTeNr2PmcPzVVaVPsyAZCSRijB4BgNVHREEcTBvghRpbnQtY2EubXljb21w
YW55LmNvbYIdaW50ZXJtZWRpYXRlLWNhLm15Y29tcGFueS5jb22GHGh0dHA6Ly9p
bnQtY2EubXljb21wYW55LmNvbS+BGmludC1jYS1hZG1pbkBteWNvbXBhbnkuY29t
MHoGA1UdHwRzMHEwM6AxoC+GLWh0dHA6Ly9jcmwubXljb21wYW55LmNvbS9teWNv
bXBhbnktaW50LWNhLmNybDA6oDigNoY0aHR0cDovL2NybC1iYWNrdXAubXljb21w
YW55LmNvbS9teWNvbXBhbnktaW50LWNhLmNybDBlBggrBgEFBQcBAQRZMFcwJQYI
KwYBBQUHMAGGGWh0dHA6Ly9vY3NwLm15Y29tcGFueS5jb20wLgYIKwYBBQUHMAKG
Imh0dHA6Ly9jYS5teWNvbXBhbnkuY29tL2ludC1jYS5jcnQwCgYIKoZIzj0EAwID
SQAwRgIhAJl5fDVmA9zRVvPIXVDLeHD0YL8uoU13EEFKN/GcvC52AiEA2jdtwrNR
tgWbVSREsxsK/9ybfUyaUhCcg1jlrwutg7E=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDvDCCA2KgAwIBAgIUe/TFUO8Fc+Ws6vLcZSOBIf09PbQwCgYIKoZIzj0EAwIw
gYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T
YW4gRnJhbmNpc2NvMRYwFAYDVQQKDA1NeUNvbXBhbnkgSW5jMREwDwYDVQQLDAhT
ZWN1cml0eTEaMBgGA1UEAwwRTXlDb21wYW55IFJvb3QgQ0EwHhcNMjUxMDI3MTQy
MjM5WhcNMzUxMDI1MTQyMjM5WjCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
bGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFjAUBgNVBAoMDU15Q29t
cGFueSBJbmMxETAPBgNVBAsMCFNlY3VyaXR5MRowGAYDVQQDDBFNeUNvbXBhbnkg
Um9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbH9E6FoEc7JulkOTFW
/opse0bQtM+rVBxiZkrE4RQ1XYgIfT/SDERX/HbRHsvfTqzPc9i2ICnP1yJsfx0W
FiSjggG0MIIBsDASBgNVHRMBAf8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjAd
BgNVHQ4EFgQUCGA03ja9j5nD81VWlT7MgGQkkYowHwYDVR0jBBgwFoAUCGA03ja9
j5nD81VWlT7MgGQkkYowZAYDVR0RBF0wW4IQY2EubXljb21wYW55LmNvbYIVcm9v
dC1jYS5teWNvbXBhbnkuY29thhhodHRwOi8vY2EubXljb21wYW55LmNvbS+BFmNh
LWFkbWluQG15Y29tcGFueS5jb20wfAYDVR0fBHUwczA0oDKgMIYuaHR0cDovL2Ny
bC5teWNvbXBhbnkuY29tL215Y29tcGFueS1yb290LWNhLmNybDA7oDmgN4Y1aHR0
cDovL2NybC1iYWNrdXAubXljb21wYW55LmNvbS9teWNvbXBhbnktcm9vdC1jYS5j
cmwwZgYIKwYBBQUHAQEEWjBYMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5teWNv
bXBhbnkuY29tMC8GCCsGAQUFBzAChiNodHRwOi8vY2EubXljb21wYW55LmNvbS9y
b290LWNhLmNydDAKBggqhkjOPQQDAgNIADBFAiEA/U11iSXRvzPfriPTkJIX+zgc
+55+glglVUTF81akovUCIFvoXh/jh+fanzVNEIOeLMdUzP7ZeSIwlbjpbSVOGjWM
-----END CERTIFICATE-----`;

// Root CA certificate for verification
const AZURE_KEY_VAULT_ROOT_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIDvDCCA2KgAwIBAgIUe/TFUO8Fc+Ws6vLcZSOBIf09PbQwCgYIKoZIzj0EAwIw
gYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T
YW4gRnJhbmNpc2NvMRYwFAYDVQQKDA1NeUNvbXBhbnkgSW5jMREwDwYDVQQLDAhT
ZWN1cml0eTEaMBgGA1UEAwwRTXlDb21wYW55IFJvb3QgQ0EwHhcNMjUxMDI3MTQy
MjM5WhcNMzUxMDI1MTQyMjM5WjCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
bGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFjAUBgNVBAoMDU15Q29t
cGFueSBJbmMxETAPBgNVBAsMCFNlY3VyaXR5MRowGAYDVQQDDBFNeUNvbXBhbnkg
Um9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbH9E6FoEc7JulkOTFW
/opse0bQtM+rVBxiZkrE4RQ1XYgIfT/SDERX/HbRHsvfTqzPc9i2ICnP1yJsfx0W
FiSjggG0MIIBsDASBgNVHRMBAf8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjAd
BgNVHQ4EFgQUCGA03ja9j5nD81VWlT7MgGQkkYowHwYDVR0jBBgwFoAUCGA03ja9
j5nD81VWlT7MgGQkkYowZAYDVR0RBF0wW4IQY2EubXljb21wYW55LmNvbYIVcm9v
dC1jYS5teWNvbXBhbnkuY29thhhodHRwOi8vY2EubXljb21wYW55LmNvbS+BFmNh
LWFkbWluQG15Y29tcGFueS5jb20wfAYDVR0fBHUwczA0oDKgMIYuaHR0cDovL2Ny
bC5teWNvbXBhbnkuY29tL215Y29tcGFueS1yb290LWNhLmNybDA7oDmgN4Y1aHR0
cDovL2NybC1iYWNrdXAubXljb21wYW55LmNvbS9teWNvbXBhbnktcm9vdC1jYS5j
cmwwZgYIKwYBBQUHAQEEWjBYMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5teWNv
bXBhbnkuY29tMC8GCCsGAQUFBzAChiNodHRwOi8vY2EubXljb21wYW55LmNvbS9y
b290LWNhLmNydDAKBggqhkjOPQQDAgNIADBFAiEA/U11iSXRvzPfriPTkJIX+zgc
+55+glglVUTF81akovUCIFvoXh/jh+fanzVNEIOeLMdUzP7ZeSIwlbjpbSVOGjWM
-----END CERTIFICATE-----`;

// Check if Azure environment variables are set
const isAzureConfigured = () => {
  return !!(
    process.env.AZURE_KEYVAULT_URL &&
    process.env.AZURE_TENANT_ID &&
    process.env.AZURE_CLIENT_ID &&
    process.env.AZURE_CLIENT_SECRET
  );
};

// Helper to get Azure configuration
const getAzureConfig = () => {
  if (!isAzureConfigured()) {
    return null;
  }

  return {
    keyVaultUrl: process.env.AZURE_KEYVAULT_URL!,
    tenantId: process.env.AZURE_TENANT_ID!,
    clientId: process.env.AZURE_CLIENT_ID!,
    clientSecret: process.env.AZURE_CLIENT_SECRET!,
    keyName: 'leaf-1-ec-hsm-key', // The HSM-managed ES256 key
  };
};

// Conditional test suite
const describeIfAzureConfigured = isAzureConfigured() ? describe : describe.skip;

describeIfAzureConfigured('Azure Key Vault integration', () => {
  let azureConfig: ReturnType<typeof getAzureConfig>;
  let signer: AzureKeyVaultSigner;

  // Get config inside beforeAll to avoid evaluation when tests are skipped
  beforeAll(() => {
    azureConfig = getAzureConfig();
    if (!azureConfig) {
      throw new Error('Azure configuration not available');
    }
  });

  beforeAll(() => {
    if (!azureConfig) return;

    // Create Azure credential
    const credential = new ClientSecretCredential(
      azureConfig.tenantId,
      azureConfig.clientId,
      azureConfig.clientSecret,
    );

    // Create the signer
    signer = new AzureKeyVaultSigner({
      keyVaultUrl: azureConfig.keyVaultUrl,
      keyName: azureConfig.keyName,
      credential,
    });
  });

  describe('AzureKeyVaultSigner', () => {
    it('should initialize successfully', () => {
      expect(signer).toBeDefined();
      expect(signer.getKeyId()).toBe(azureConfig!.keyName);
    });

    it('should retrieve the public key from Azure Key Vault', async () => {
      const publicKey = await signer.getPublicKey();
      expect(publicKey).toBeDefined();
      expect(publicKey.kty).toBe('EC');
      expect(publicKey.crv).toBe('P-256'); // ES256 uses P-256
      expect(publicKey.x).toBeDefined();
      expect(publicKey.y).toBeDefined();
      expect(publicKey.d).toBeUndefined(); // Should not have private key component
    }, 10000); // 10 second timeout for network call

    it('should sign data using Azure Key Vault', async () => {
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = await signer.sign('ES256', testData);

      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
      // ES256 signatures are typically 64 bytes (DER encoded can be slightly longer)
      expect(signature.length).toBeGreaterThanOrEqual(64);
    }, 10000);
  });

  describe('issuing an MDOC with Azure Key Vault', () => {
    let encoded: Uint8Array;
    let parsedDocument: IssuerSignedDocument;

    // Use dates within the certificate validity period (Oct 27, 2025 - Oct 27, 2026)
    // Truncate to seconds to match CBOR encoding
    const now = new Date();
    now.setMilliseconds(0);
    const signed = new Date(now);
    signed.setHours(signed.getHours() - 1); // Signed 1 hour ago
    const validFrom = new Date(signed);
    validFrom.setMinutes(signed.getMinutes() - 10); // Valid from 10 minutes before signing
    const validUntil = new Date(signed);
    validUntil.setMonth(signed.getMonth() + 6); // 6 months validity
    const expectedUpdate = new Date(signed);
    expectedUpdate.setMonth(signed.getMonth() + 1); // Update in 1 month

    beforeAll(async () => {
      const document = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Smith',
          given_name: 'Alice',
          birth_date: '1990-05-15',
          issue_date: '2024-01-15',
          expiry_date: '2034-01-15',
          issuing_country: 'US',
          issuing_authority: 'CA DMV',
          document_number: 'AKV123456',
          portrait: 'bstr',
          driving_privileges: [
            {
              vehicle_category_code: 'C',
              issue_date: '2024-01-15',
              expiry_date: '2034-01-15',
            },
          ],
        })
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed,
          validFrom,
          validUntil,
          expectedUpdate,
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          signer, // Use Azure Key Vault signer
          issuerCertificate: AZURE_KEY_VAULT_CERTIFICATE_CHAIN,
          alg: 'ES256',
        });

      const mdoc = new MDoc([document]);
      const encodedBuffer = mdoc.encode();
      encoded = new Uint8Array(encodedBuffer);

      const parsedMDOC = parse(encoded);
      [parsedDocument] = parsedMDOC.documents;
    }, 15000); // 15 second timeout for signing operation

    it('should create a valid signed document', () => {
      expect(encoded).toBeDefined();
      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded.length).toBeGreaterThan(0);
    });

    it('should be verifiable with the matching Azure Key Vault certificate', async () => {
      // Full cryptographic signature verification with matching certificate
      const verifier = new Verifier([AZURE_KEY_VAULT_ROOT_CERTIFICATE]);
      await verifier.verify(encoded, {
        onCheck: (verification, original) => {
          // Skip device auth verification since we're only testing issuer signature
          if (verification.category === 'DEVICE_AUTH') {
            return;
          }
          original(verification);
        },
      });

      // Verify structure as well
      expect(parsedDocument).toBeDefined();
      expect(parsedDocument.issuerSigned).toBeDefined();
      expect(parsedDocument.issuerSigned.issuerAuth).toBeDefined();
      expect(parsedDocument.issuerSigned.issuerAuth.signature).toBeInstanceOf(Uint8Array);
      expect(parsedDocument.issuerSigned.issuerAuth.signature.length).toBeGreaterThan(0);
    });

    it('should contain the correct validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
      expect(validityInfo).toBeDefined();
      // Dates should match exactly since we truncated milliseconds
      expect(validityInfo.signed).toEqual(signed);
      expect(validityInfo.validFrom).toEqual(validFrom);
      expect(validityInfo.validUntil).toEqual(validUntil);
      expect(validityInfo.expectedUpdate).toBeDefined();
      expect(validityInfo.expectedUpdate).toEqual(expectedUpdate);
    });

    it('should use the correct digest algorithm', () => {
      const { digestAlgorithm } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
      expect(digestAlgorithm).toEqual('SHA-256');
    });

    it('should include the device public key', () => {
      const { deviceKeyInfo } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
      expect(deviceKeyInfo?.deviceKey).toBeDefined();
      const actual = typeof deviceKeyInfo !== 'undefined' &&
        COSEKeyToJWK(deviceKeyInfo.deviceKey);
      expect(actual).toEqual(publicKeyJWK);
    });

    it('should include the namespace and attributes', () => {
      const attrValues = parsedDocument.getIssuerNameSpace('org.iso.18013.5.1');
      expect(attrValues).toBeDefined();
      expect(attrValues.family_name).toBe('Smith');
      expect(attrValues.given_name).toBe('Alice');
      expect(attrValues.birth_date.toString()).toBe('1990-05-15');
      expect(attrValues.document_number).toBe('AKV123456');
      expect(attrValues.issuing_country).toBe('US');
      expect(attrValues.issuing_authority).toBe('CA DMV');
    });

    it('should have a valid COSE signature structure', () => {
      const { issuerAuth } = parsedDocument.issuerSigned;
      expect(issuerAuth).toBeDefined();
      expect(issuerAuth.payload).toBeDefined();
      expect(issuerAuth.signature).toBeDefined();
      expect(issuerAuth.signature.length).toBeGreaterThan(0);
    });
  });

  describe('comparison with local key signing', () => {
    it('both should produce valid COSE structures', async () => {
      // Sign with Azure Key Vault
      const azureDoc = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Test',
          given_name: 'Azure',
          birth_date: '1990-01-01',
          issue_date: '2024-01-01',
          expiry_date: '2034-01-01',
          issuing_country: 'US',
          document_number: 'AZ001',
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          signer,
          issuerCertificate: AZURE_KEY_VAULT_CERTIFICATE_CHAIN,
          alg: 'ES256',
        });

      // Sign with local key (traditional method)
      const localDoc = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Test',
          given_name: 'Local',
          birth_date: '1990-01-01',
          issue_date: '2024-01-01',
          expiry_date: '2034-01-01',
          issuing_country: 'US',
          document_number: 'LOC001',
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          issuerPrivateKey: {
            kty: 'EC',
            kid: '1234',
            x: 'iTwtg0eQbcbNabf2Nq9L_VM_lhhPCq2s0Qgw2kRx29s',
            y: 'YKwXDRz8U0-uLZ3NSI93R_35eNkl6jHp6Qg8OCup7VM',
            crv: 'P-256',
            d: 'o6PrzBm1dCfSwqJHW6DVqmJOCQSIAosrCPfbFJDMNp4',
          },
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        });

      // Both should encode successfully
      const azureEncoded = new Uint8Array(new MDoc([azureDoc]).encode());
      const localEncoded = new Uint8Array(new MDoc([localDoc]).encode());

      expect(azureEncoded).toBeDefined();
      expect(localEncoded).toBeDefined();

      // Both should be parseable
      const parsedAzure = parse(azureEncoded);
      const parsedLocal = parse(localEncoded);

      expect(parsedAzure.documents).toHaveLength(1);
      expect(parsedLocal.documents).toHaveLength(1);

      // Local doc should be verifiable with its matching certificate
      const localVerifier = new Verifier([ISSUER_CERTIFICATE]);
      await localVerifier.verify(localEncoded, {
        onCheck: (v, o) => (v.category === 'DEVICE_AUTH' ? undefined : o(v)),
      });

      // Azure doc should also be verifiable with its matching certificate
      const azureVerifier = new Verifier([AZURE_KEY_VAULT_ROOT_CERTIFICATE]);
      await azureVerifier.verify(azureEncoded, {
        onCheck: (v, o) => (v.category === 'DEVICE_AUTH' ? undefined : o(v)),
      });

      // Both signatures should be valid
      expect(parsedAzure.documents[0].issuerSigned.issuerAuth.signature).toBeInstanceOf(Uint8Array);
      expect(parsedAzure.documents[0].issuerSigned.issuerAuth.signature.length).toBeGreaterThan(0);
      expect(parsedLocal.documents[0].issuerSigned.issuerAuth.signature).toBeInstanceOf(Uint8Array);
      expect(parsedLocal.documents[0].issuerSigned.issuerAuth.signature.length).toBeGreaterThan(0);
    }, 15000);
  });
});

// Always run this describe block to show helpful message when Azure is not configured
describe('Azure Key Vault integration (configuration check)', () => {
  if (!isAzureConfigured()) {
    it('should skip tests when Azure environment is not configured', () => {
      console.log('\n⚠️  Azure Key Vault tests skipped');
      console.log('To enable these tests, source the azure-env.sh file:');
      console.log('  source azure-env.sh');
      console.log('  npm test');
      console.log('\nRequired environment variables:');
      console.log('  - AZURE_KEYVAULT_URL');
      console.log('  - AZURE_TENANT_ID');
      console.log('  - AZURE_CLIENT_ID');
      console.log('  - AZURE_CLIENT_SECRET\n');
    });
  } else {
    it('Azure environment is configured', () => {
      const config = getAzureConfig();
      expect(config).toBeDefined();
      expect(config?.keyVaultUrl).toBeDefined();
      expect(config?.keyName).toBe('leaf-1-ec-hsm-key');
    });
  }
});
