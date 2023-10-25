import * as jose from 'jose';
import { COSEKeyToJWK } from 'cose-kit';
import {
  MDoc,
  Document,
  Verifier,
  parse,
  IssuerSignedDocument,
} from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_CERTIFICATE_PRIVATE_KEY } from './config';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

describe('issuing an MDOC', () => {
  let encoded: Uint8Array;
  let parsedDocument: IssuerSignedDocument;

  beforeAll(async () => {
    const issuerPrivateKey = await jose.importPKCS8(ISSUER_CERTIFICATE_PRIVATE_KEY, '');

    const document = await new Document('org.iso.18013.5.1.mDL')
      .addIssuerNameSpace('org.iso.18013.5.1', {
        family_name: 'Jones',
        given_name: 'Ava',
        birth_date: '2007-03-25',
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
      });

    const mdoc = new MDoc([document]);
    encoded = mdoc.encode();

    const parsedMDOC = parse(encoded);
    [parsedDocument] = parsedMDOC.documents;
  });

  it('should be verifiable', async () => {
    const verifier = new Verifier([ISSUER_CERTIFICATE]);
    await verifier.verify(encoded, {
      onCheck: (verification, original) => {
        if (verification.category === 'DEVICE_AUTH') {
          return;
        }
        original(verification);
      },
    });
  });

  it('should contain the validity info', () => {
    const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(validityInfo).toBeDefined();
    expect(validityInfo.signed).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validFrom).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validUntil).toEqual(new Date('2050-10-24'));
  });

  it('should use the correct digest alg', () => {
    const { digestAlgorithm } = parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(digestAlgorithm).toEqual('SHA-512');
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
    console.dir(parsedDocument.issuerSigned);
    expect(attrValues).toMatchInlineSnapshot(`
{
  "age_over_16": 16,
  "age_over_21": false,
  "birth_date": "2007-03-25",
  "family_name": "Jones",
  "given_name": "Ava",
}
`);
  });
});
