import * as jose from 'jose';
import { MDoc, Document, Verifier } from '../../src';
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_CERTIFICATE_PRIVATE_KEY } from './config';

describe('issuing an MDOC', () => {
  let encoded: Uint8Array;

  beforeAll(async () => {
    const issuerPrivateKey = await jose.importPKCS8(ISSUER_CERTIFICATE_PRIVATE_KEY, '');
    const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

    const document = await new Document('org.iso.18013.5.1.mDL')
      .addIssuerNameSpace('org.iso.18013.5.1', {
        family_name: 'Jones',
        given_name: 'Ava',
        birth_date: '2007-03-25',
      })
      .useDigestAlgorithm('SHA-256')
      .addValidityInfo({
        signed: new Date(),
      })
      .addDeviceKeyInfo({ devicePublicKey: publicKeyJWK })
      .sign({
        issuerPrivateKey,
        issuerCertificate: ISSUER_CERTIFICATE,
      });

    const mdoc = new MDoc([document]);
    encoded = mdoc.encode();
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
});
