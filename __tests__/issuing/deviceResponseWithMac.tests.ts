import { randomFillSync } from 'node:crypto';
import * as jose from 'jose';
import { COSEKeyFromJWK } from 'cose-kit';
import {
  MDoc,
  Document,
  Verifier,
  parse,
  DeviceResponse,
  DeviceSignedDocument,
} from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK, PRESENTATION_DEFINITION_1 } from './config';
import { DataItem, cborEncode } from '../../src/cbor';
import COSEKeyToRAW from '../../src/cose/coseKey';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

describe('issuing a device response with MAC authentication', () => {
  let encoded: Uint8Array;
  let parsedDocument: DeviceSignedDocument;
  let mdoc: MDoc;
  let ephemeralPrivateKey: Uint8Array;
  let ephemeralPublicKey: Uint8Array;

  const signed = new Date('2023-10-24T14:55:18Z');
  const validUntil = new Date(signed);
  validUntil.setFullYear(signed.getFullYear() + 30);

  beforeAll(async () => {
    const issuerPrivateKey = ISSUER_PRIVATE_KEY_JWK;

    // this is the ISSUER side
    {
      const document = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
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
              vehicle_category_code: 'C',
              issue_date: '2022-09-01',
              expiry_date: '2027-09-30',
            },
          ],
          un_distinguishing_sign: 'tbd-us.ny.dmv',

          sex: 'F',
          height: '5\' 8"',
          weight: '120lb',
          eye_colour: 'brown',
          hair_colour: 'brown',
          resident_addres: '123 Street Rd',
          resident_city: 'Brooklyn',
          resident_state: 'NY',
          resident_postal_code: '19001',
          resident_country: 'US',
          issuing_jurisdiction: 'New York',
        })
        .useDigestAlgorithm('SHA-512')
        .addValidityInfo({
          signed,
          validUntil,
        })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign({
          issuerPrivateKey,
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        });

      mdoc = new MDoc([document]);

      // This is the verifier side before requesting the Device Response
      {
        const ephemeralKey = await jose.exportJWK((await jose.generateKeyPair('ES256')).privateKey);
        const { d: _1, ...ephemeralKeyPublic } = ephemeralKey;
        ephemeralPrivateKey = COSEKeyToRAW(COSEKeyFromJWK(ephemeralKey));
        ephemeralPublicKey = COSEKeyToRAW(COSEKeyFromJWK(ephemeralKeyPublic));
      }
    }
  });

  describe('using OID4VP handover', () => {
    const verifierGeneratedNonce = 'abcdefg';
    const mdocGeneratedNonce = '123456';
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4';
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback';

    const getSessionTranscriptBytes = (clId: string, respUri: string, nonce: string, mdocNonce: string) => cborEncode(
      DataItem.fromData([
        null, // DeviceEngagementBytes
        null, // EReaderKeyBytes
        [mdocNonce, clId, respUri, nonce], // Handover = OID4VPHandover
      ]),
    );

    beforeAll(async () => {
      //  This is the Device side
      const deviceResponseMDoc = await DeviceResponse.from(mdoc)
        .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
        .usingSessionTranscriptForOID4VP(mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce)
        .authenticateWithMAC(DEVICE_JWK, ephemeralPublicKey, 'HS256')
        .addDeviceNameSpace('com.foobar-device', { test: 1234 })
        .sign();

      encoded = deviceResponseMDoc.encode();
      const parsedMDOC = parse(encoded);
      [parsedDocument] = parsedMDOC.documents as DeviceSignedDocument[];
    });

    it('should be verifiable', async () => {
      const verifier = new Verifier([ISSUER_CERTIFICATE]);
      await verifier.verify(encoded, {
        ephemeralReaderKey: ephemeralPrivateKey,
        encodedSessionTranscript: getSessionTranscriptBytes(clientId, responseUri, verifierGeneratedNonce, mdocGeneratedNonce),
      });
    });

    describe('should not be verifiable', () => {
      [
        ['clientId', { clientId: 'wrong', responseUri, verifierGeneratedNonce, mdocGeneratedNonce }] as const,
        ['responseUri', { clientId, responseUri: 'wrong', verifierGeneratedNonce, mdocGeneratedNonce }] as const,
        ['verifierGeneratedNonce', { clientId, responseUri, verifierGeneratedNonce: 'wrong', mdocGeneratedNonce }] as const,
        ['mdocGeneratedNonce', { clientId, responseUri, verifierGeneratedNonce, mdocGeneratedNonce: 'wrong' }] as const,
      ].forEach(([name, values]) => {
        it(`with a different ${name}`, async () => {
          try {
            const verifier = new Verifier([ISSUER_CERTIFICATE]);
            await verifier.verify(encoded, {
              ephemeralReaderKey: ephemeralPrivateKey,
              encodedSessionTranscript: getSessionTranscriptBytes(values.clientId, values.responseUri, values.verifierGeneratedNonce, values.mdocGeneratedNonce),
            });
            throw new Error('should not validate with different transcripts');
          } catch (error) {
            expect(error.message).toMatch('Unable to verify deviceAuth MAC: Device MAC must be valid');
          }
        });
      });
    });

    it('should generate a device mac without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceMac?.payload).toBeNull();
    });

    it('should contain the validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
      expect(validityInfo).toBeDefined();
      expect(validityInfo.signed).toEqual(signed);
      expect(validityInfo.validFrom).toEqual(signed);
      expect(validityInfo.validUntil).toEqual(validUntil);
      expect(validityInfo.expectedUpdate).toBeUndefined();
    });

    it('should contain the device namespaces', () => {
      expect(parsedDocument.getDeviceNameSpace('com.foobar-device'))
        .toEqual({ test: 1234 });
    });
  });

  describe('using WebAPI handover', () => {
    // The actual value for the engagements & the key do not matter,
    // as long as the device and the reader agree on what value to use.
    const eReaderKeyBytes: Buffer = randomFillSync(Buffer.alloc(32));
    const readerEngagementBytes = randomFillSync(Buffer.alloc(32));
    const deviceEngagementBytes = randomFillSync(Buffer.alloc(32));

    const getSessionTranscriptBytes = (
      rdrEngtBytes: Buffer,
      devEngtBytes: Buffer,
      eRdrKeyBytes: Buffer,
    ) => cborEncode(
      DataItem.fromData([
        new DataItem({ buffer: devEngtBytes }),
        new DataItem({ buffer: eRdrKeyBytes }),
        rdrEngtBytes,
      ]),
    );

    beforeAll(async () => {
      // This is the verifier side before requesting the Device Response
      {
        const ephemeralKey = await jose.exportJWK((await jose.generateKeyPair('ES256')).privateKey);
        ephemeralPrivateKey = COSEKeyToRAW(COSEKeyFromJWK(ephemeralKey));
        const { d: _1, ...ephemeralKeyPublic } = ephemeralKey;
        ephemeralPublicKey = COSEKeyToRAW(COSEKeyFromJWK(ephemeralKeyPublic));
      }

      //  This is the Device side
      {
        const deviceResponseMDoc = await DeviceResponse.from(mdoc)
          .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
          .usingSessionTranscriptForWebAPI(deviceEngagementBytes, readerEngagementBytes, eReaderKeyBytes)
          .authenticateWithMAC(DEVICE_JWK, ephemeralPublicKey, 'HS256')
          .addDeviceNameSpace('com.foobar-device', { test: 1234 })
          .sign();
        encoded = deviceResponseMDoc.encode();
      }

      const parsedMDOC = parse(encoded);
      [parsedDocument] = parsedMDOC.documents as DeviceSignedDocument[];
    });

    it('should be verifiable', async () => {
      const verifier = new Verifier([ISSUER_CERTIFICATE]);
      await verifier.verify(encoded, {
        ephemeralReaderKey: ephemeralPrivateKey,
        encodedSessionTranscript: getSessionTranscriptBytes(readerEngagementBytes, deviceEngagementBytes, eReaderKeyBytes),
      });
    });

    describe('should not be verifiable', () => {
      const wrong = randomFillSync(Buffer.alloc(32));
      [
        ['readerEngagementBytes', { readerEngagementBytes: wrong, deviceEngagementBytes, eReaderKeyBytes }] as const,
        ['deviceEngagementBytes', { readerEngagementBytes, deviceEngagementBytes: wrong, eReaderKeyBytes }] as const,
        ['eReaderKeyBytes', { readerEngagementBytes, deviceEngagementBytes, eReaderKeyBytes: wrong }] as const,
      ].forEach(([name, values]) => {
        it(`with a different ${name}`, async () => {
          const verifier = new Verifier([ISSUER_CERTIFICATE]);
          try {
            await verifier.verify(encoded, {
              ephemeralReaderKey: ephemeralPrivateKey,
              encodedSessionTranscript: getSessionTranscriptBytes(values.readerEngagementBytes, values.deviceEngagementBytes, values.eReaderKeyBytes),
            });
            throw new Error('should not validate with different transcripts');
          } catch (error) {
            expect(error.message).toMatch('Unable to verify deviceAuth MAC: Device MAC must be valid');
          }
        });
      });
    });

    it('should generate a device mac without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceMac?.payload).toBeNull();
    });

    it('should contain the validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
      expect(validityInfo).toBeDefined();
      expect(validityInfo.signed).toEqual(signed);
      expect(validityInfo.validFrom).toEqual(signed);
      expect(validityInfo.validUntil).toEqual(validUntil);
      expect(validityInfo.expectedUpdate).toBeUndefined();
    });

    it('should contain the device namespaces', () => {
      expect(parsedDocument.getDeviceNameSpace('com.foobar-device'))
        .toEqual({ test: 1234 });
    });
  });
});
