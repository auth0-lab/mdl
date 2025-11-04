import * as jose from 'jose';
import {
  Document,
  LocalKeySigner,
  MDoc,
  parse,
  Verifier,
} from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from './config';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

describe('Signer Compatibility Tests', () => {
  const signed = new Date('2023-10-24T14:55:18Z');
  const validFrom = new Date(signed);
  validFrom.setMinutes(signed.getMinutes() + 5);
  const validUntil = new Date(signed);
  validUntil.setFullYear(signed.getFullYear() + 30);
  const expectedUpdate = new Date(signed);
  expectedUpdate.setFullYear(signed.getFullYear() + 1);

  const sharedDocumentData = {
    family_name: 'Jones',
    given_name: 'Ava',
    birth_date: '2007-03-25',
    issue_date: '2023-09-01',
    expiry_date: '2028-09-30',
    issuing_country: 'US',
    issuing_authority: 'NY DMV',
    document_number: '01-856-5050',
    portrait: 'bstr',
    driving_privileges: [
      {
        vehicle_category_code: 'A',
        issue_date: '2021-09-02',
        expiry_date: '2026-09-20',
      },
      {
        vehicle_category_code: 'B',
        issue_date: '2022-09-02',
        expiry_date: '2027-09-20',
      },
    ],
  };

  describe('Document.sign() - Old vs New Method', () => {
    let encodedWithOldMethod: Uint8Array;
    let encodedWithNewMethod: Uint8Array;

    beforeAll(async () => {
      // Sign with old method using issuerPrivateKey
      const docOld = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', sharedDocumentData)
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed,
          validFrom,
          validUntil,
          expectedUpdate,
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          issuerPrivateKey: ISSUER_PRIVATE_KEY_JWK,
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        });

      const mdocOld = new MDoc([docOld]);
      encodedWithOldMethod = mdocOld.encode();

      // Sign with new method using LocalKeySigner
      const signer = new LocalKeySigner(ISSUER_PRIVATE_KEY_JWK, 'ES256');
      const docNew = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', sharedDocumentData)
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed,
          validFrom,
          validUntil,
          expectedUpdate,
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          signer,
          issuerCertificate: ISSUER_CERTIFICATE,
        });

      const mdocNew = new MDoc([docNew]);
      encodedWithNewMethod = mdocNew.encode();
    });

    it('should produce valid documents with both methods', () => {
      expect(encodedWithOldMethod).toBeDefined();
      expect(encodedWithOldMethod).toBeInstanceOf(Uint8Array);
      expect(encodedWithOldMethod.length).toBeGreaterThan(0);

      expect(encodedWithNewMethod).toBeDefined();
      expect(encodedWithNewMethod).toBeInstanceOf(Uint8Array);
      expect(encodedWithNewMethod.length).toBeGreaterThan(0);
    });

    it('should both be verifiable by the Verifier', async () => {
      const verifier = new Verifier([ISSUER_CERTIFICATE]);

      // Verify old method document
      await expect(
        verifier.verify(encodedWithOldMethod, {
          onCheck: (verification, original) => {
            if (verification.category === 'DEVICE_AUTH') {
              return;
            }
            original(verification);
          },
        }),
      ).resolves.not.toThrow();

      // Verify new method document
      await expect(
        verifier.verify(encodedWithNewMethod, {
          onCheck: (verification, original) => {
            if (verification.category === 'DEVICE_AUTH') {
              return;
            }
            original(verification);
          },
        }),
      ).resolves.not.toThrow();
    });

    it('should produce documents with identical structure', () => {
      const parsedOld = parse(encodedWithOldMethod);
      const parsedNew = parse(encodedWithNewMethod);

      const docOld = parsedOld.documents[0];
      const docNew = parsedNew.documents[0];

      // Compare document type
      expect(docOld.docType).toEqual(docNew.docType);

      // Compare validity info
      const validityInfoOld = docOld.issuerSigned.issuerAuth.decodedPayload.validityInfo;
      const validityInfoNew = docNew.issuerSigned.issuerAuth.decodedPayload.validityInfo;
      expect(validityInfoOld.signed).toEqual(validityInfoNew.signed);
      expect(validityInfoOld.validFrom).toEqual(validityInfoNew.validFrom);
      expect(validityInfoOld.validUntil).toEqual(validityInfoNew.validUntil);
      expect(validityInfoOld.expectedUpdate).toEqual(validityInfoNew.expectedUpdate);

      // Compare digest algorithm
      expect(docOld.issuerSigned.issuerAuth.decodedPayload.digestAlgorithm)
        .toEqual(docNew.issuerSigned.issuerAuth.decodedPayload.digestAlgorithm);

      // Compare namespace data
      const attrValuesOld = docOld.getIssuerNameSpace('org.iso.18013.5.1');
      const attrValuesNew = docNew.getIssuerNameSpace('org.iso.18013.5.1');
      expect(attrValuesOld).toEqual(attrValuesNew);
    });

    it('should have the same algorithm identifier', () => {
      const parsedOld = parse(encodedWithOldMethod);
      const parsedNew = parse(encodedWithNewMethod);

      const docOld = parsedOld.documents[0];
      const docNew = parsedNew.documents[0];

      // Both documents should use ES256 (-7)
      expect(docOld.issuerSigned.issuerAuth.alg).toEqual(docNew.issuerSigned.issuerAuth.alg);
      expect(docOld.issuerSigned.issuerAuth.alg).toEqual(-7); // -7 is the COSE algorithm identifier for ES256
    });

    it('should have valid COSE signatures with both methods', () => {
      const parsedOld = parse(encodedWithOldMethod);
      const parsedNew = parse(encodedWithNewMethod);

      const docOld = parsedOld.documents[0];
      const docNew = parsedNew.documents[0];

      // Both should have valid signatures
      expect(docOld.issuerSigned.issuerAuth.signature).toBeInstanceOf(Uint8Array);
      expect(docOld.issuerSigned.issuerAuth.signature.length).toBeGreaterThan(0);

      expect(docNew.issuerSigned.issuerAuth.signature).toBeInstanceOf(Uint8Array);
      expect(docNew.issuerSigned.issuerAuth.signature.length).toBeGreaterThan(0);

      // Signatures will be different due to randomness in ECDSA signing,
      // but both should be valid (verified by the Verifier test above)
    });
  });

  describe('LocalKeySigner implementation', () => {
    it('should correctly implement the Signer interface', () => {
      const signer = new LocalKeySigner(ISSUER_PRIVATE_KEY_JWK, 'ES256');

      expect(signer.getKeyId()).toBe(ISSUER_PRIVATE_KEY_JWK.kid);
      expect(signer.getAlgorithm()).toBe('ES256');
    });

    it('should be able to sign data', async () => {
      const signer = new LocalKeySigner(ISSUER_PRIVATE_KEY_JWK, 'ES256');
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = await signer.sign(testData);

      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
    });
  });

  describe('Backward compatibility', () => {
    it('should still support the old issuerPrivateKey method', async () => {
      const doc = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Test',
          given_name: 'User',
          birth_date: '1990-01-01',
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          issuerPrivateKey: ISSUER_PRIVATE_KEY_JWK,
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        });

      const mdoc = new MDoc([doc]);
      const encoded = mdoc.encode();
      const verifier = new Verifier([ISSUER_CERTIFICATE]);

      await expect(
        verifier.verify(encoded, {
          onCheck: (verification, original) => {
            if (verification.category === 'DEVICE_AUTH') {
              return;
            }
            original(verification);
          },
        }),
      ).resolves.not.toThrow();
    });

    it('should reject when both issuerPrivateKey and signer are provided', async () => {
      const signer = new LocalKeySigner(ISSUER_PRIVATE_KEY_JWK, 'ES256');
      const doc = new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Test',
          given_name: 'User',
          birth_date: '1990-01-01',
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK });

      await expect(
        doc.sign({
          issuerPrivateKey: ISSUER_PRIVATE_KEY_JWK, // Old method
          signer, // New method
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        } as any),
      ).rejects.toThrow('Cannot provide both issuerPrivateKey and signer');
    });

    it('should reject when neither issuerPrivateKey nor signer is provided', async () => {
      const doc = new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Test',
          given_name: 'User',
          birth_date: '1990-01-01',
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK });

      await expect(
        doc.sign({
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        } as any),
      ).rejects.toThrow('Must provide either issuerPrivateKey or signer');
    });
  });
});
