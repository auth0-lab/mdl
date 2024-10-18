import * as jose from 'jose';
import { COSEKeyToJWK } from 'cose-kit';
import {
  MDoc,
  Document,
  Verifier,
  parse,
  IssuerSignedDocument,
} from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from './config';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

describe('issuing an MDOC', () => {
  let encoded: Uint8Array;
  let parsedDocument: IssuerSignedDocument;

  const signed = new Date('2023-10-24T14:55:18Z');
  const validFrom = new Date(signed);
  validFrom.setMinutes(signed.getMinutes() + 5);
  const validUntil = new Date(signed);
  validUntil.setFullYear(signed.getFullYear() + 30);

  beforeAll(async () => {
    const issuerPrivateKey = ISSUER_PRIVATE_KEY_JWK;

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
      })
      .useDigestAlgorithm('SHA-512')
      .addValidityInfo({
        signed,
        validFrom,
        validUntil,
      })
      .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
      .sign({
        issuerPrivateKey,
        issuerCertificate: ISSUER_CERTIFICATE,
        alg: 'ES256',
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
    expect(validityInfo.signed).toEqual(signed);
    expect(validityInfo.validFrom).toEqual(validFrom);
    expect(validityInfo.validUntil).toEqual(validUntil);
    expect(validityInfo.expectedUpdate).toBeUndefined();
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
    // @ts-ignore
    const currentAge = new Date(Date.now() - new Date('2007-03-25')).getFullYear() - 1970;
    expect(attrValues).toMatchInlineSnapshot(`
{
  "age_over_${currentAge}": true,
  "age_over_21": ${currentAge >= 21},
  "birth_date": "2007-03-25",
  "document_number": "01-856-5050",
  "driving_privileges": [
    Map {
      "vehicle_category_code" => "A",
      "issue_date" => "2021-09-02",
      "expiry_date" => "2026-09-20",
    },
    Map {
      "vehicle_category_code" => "B",
      "issue_date" => "2022-09-02",
      "expiry_date" => "2027-09-20",
    },
  ],
  "expiry_date": "2028-09-30",
  "family_name": "Jones",
  "given_name": "Ava",
  "issue_date": "2023-09-01",
  "issuing_authority": "NY DMV",
  "issuing_country": "US",
  "portrait": "bstr",
}
`);
  });
});
