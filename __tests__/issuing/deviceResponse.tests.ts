import * as jose from 'jose';
import {
  MDoc,
  Document,
  Verifier,
  parse,
  DeviceResponse,
} from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK, PRESENTATION_DEFINITION_1 } from './config';
import { DataItem, cborEncode } from '../../src/cbor';
import { DeviceSignedDocument } from '../../src/mdoc/model/IssuerSignedDocument';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

const getSessionTranscriptBytes = ({ client_id: clientId, response_uri: responseUri, nonce }, mdocGeneratedNonce) => cborEncode(
  DataItem.fromData([
    null, // DeviceEngagementBytes
    null, // EReaderKeyBytes
    [mdocGeneratedNonce, clientId, responseUri, nonce], // Handover = OID4VPHandover
  ]),
);

describe('issuing a device response', () => {
  let encoded: Uint8Array;
  let parsedDocument: DeviceSignedDocument;
  let mdoc: MDoc;
  let ephemeralReaderKey: Buffer;
  let encodedSessionTranscript: Buffer;

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
          expiry_date: '2028-09-31',
          issuing_country: 'US',
          issuing_authority: 'NY DMV',
          document_number: '01-856-5050',
          portrait: 'bstr',
          driving_privileges: [
            {
              vehicle_category_code: 'C',
              issue_date: '2023-09-01',
              expiry_date: '2028-09-31',
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
          signed: new Date('2023-10-24'),
          validUntil: new Date('2050-10-24'),
        })
        .addDeviceKeyInfo({ devicePublicKey: publicKeyJWK })
        .sign({
          issuerPrivateKey,
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        });

      mdoc = new MDoc([document]);
    }

    //  This is the Device side
    {
      const verifierGeneratedNonce = 'abcdefg';
      const mdocGeneratedNonce = '123456';
      const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4';
      const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback';
      const devicePrivateKey = DEVICE_JWK;

      const deviceResponseMDoc = await DeviceResponse.from(mdoc)
        .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
        .usingHandover([mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce])
        .authenticateWithSignature(devicePrivateKey, 'ES256')
        .addDeviceNameSpace('com.foobar-device', { test: 1234 })
        .sign();

      ephemeralReaderKey = Buffer.from('SKReader', 'utf8');
      encodedSessionTranscript = getSessionTranscriptBytes(
        { client_id: clientId, response_uri: responseUri, nonce: verifierGeneratedNonce },
        mdocGeneratedNonce,
      );

      encoded = deviceResponseMDoc.encode();
    }

    const parsedMDOC = parse(encoded);
    [parsedDocument] = parsedMDOC.documents as DeviceSignedDocument[];
  });

  it('should be verifiable', async () => {
    const verifier = new Verifier([ISSUER_CERTIFICATE]);
    await verifier.verify(encoded, {
      ephemeralReaderKey,
      encodedSessionTranscript,
    });
  });

  it('should contain the validity info', () => {
    const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(validityInfo).toBeDefined();
    expect(validityInfo.signed).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validFrom).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validUntil).toEqual(new Date('2050-10-24'));
  });

  it('should contain the device namespaces', () => {
    expect(parsedDocument.getDeviceNameSpace('com.foobar-device'))
      .toEqual({ test: 1234 });
  });
});