import * as jose from 'jose';
import { COSEKeyToJWK } from 'cose-kit';
import { ClientSecretCredential } from '@azure/identity';
import {
  MDoc,
  Document,
  parse,
  IssuerSignedDocument,
} from '../../../src';
import { AzureKeyVaultSigner } from '../src/AzureKeyVaultSigner';
import { DEVICE_JWK, ISSUER_CERTIFICATE } from '../../../__tests__/issuing/config';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

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

describeIfAzureConfigured('Azure Key Vault Signer Example', () => {
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
      algorithm: 'ES256', // The test key is ES256
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
      const signature = await signer.sign(testData);

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
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          signer, // Use Azure Key Vault signer
          issuerCertificate: ISSUER_CERTIFICATE,
          // alg is inferred from signer.getAlgorithm()
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

    it('should have a valid COSE signature structure', () => {
      expect(parsedDocument).toBeDefined();
      expect(parsedDocument.issuerSigned).toBeDefined();
      expect(parsedDocument.issuerSigned.issuerAuth).toBeDefined();
      expect(parsedDocument.issuerSigned.issuerAuth.signature).toBeInstanceOf(Uint8Array);
      expect(parsedDocument.issuerSigned.issuerAuth.signature.length).toBeGreaterThan(0);
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
  });
});

// Always run this describe block to show helpful message when Azure is not configured
describe('Azure Key Vault Signer Example (configuration check)', () => {
  if (!isAzureConfigured()) {
    it('should skip tests when Azure environment is not configured', () => {
      console.log('\n⚠️  Azure Key Vault Signer example tests skipped');
      console.log('To enable these tests, set up your Azure environment:');
      console.log('  1. Copy examples/azure-keyvault-signer/sample-azure-env.sh');
      console.log('  2. Fill in your Azure Key Vault credentials');
      console.log('  3. source azure-env.sh');
      console.log('  4. npm test');
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
