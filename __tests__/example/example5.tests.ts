import * as jose from 'jose';
import * as crypto from 'crypto';
import fs from 'fs';
import { Verifier, Document, MDoc, DeviceResponse } from '../../src/index';

describe('example 5: device response contains a partial x5chain of the issuer certificate', () => {
  it('issuer signature should be valid', async () => {
    const devicePrivatePEM = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKWuHzvetdYpe5cErlOrU1bipA0OFtbBpJBdXCzRIVbz\n-----END PRIVATE KEY-----';
    const devicePrivateKey = await jose.exportJWK(crypto.createPrivateKey({ key: devicePrivatePEM }));
    const devicePublicKey: jose.JWK = {
      kty: devicePrivateKey.kty,
      crv: devicePrivateKey.crv,
      x: devicePrivateKey.x,
    };

    // A test IACA Root Certificate that the Issuer has shared publicly
    // The openssl command to generate this certificate can be found @ https://github.com/auth0-lab/mdl/issues/37#issuecomment-2618717656
    const issuerIacaRootCertificate = '-----BEGIN CERTIFICATE-----\nMIICuzCCAh2gAwIBAgIUS9ewqx43m6VHiP5koCeEd09JOIwwCgYIKoZIzj0EAwQw\nOzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDEeMBwGA1UEAwwVSUFDQSBSb290\nIENlcnRpZmljYXRlMB4XDTI1MDEyODEyNTUzNloXDTM1MDEyNjEyNTUzNlowOzEL\nMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDEeMBwGA1UEAwwVSUFDQSBSb290IENl\ncnRpZmljYXRlMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBBt6kxI26+zkCddEN\ntuCUddthenpnDC7yT2ZgNvisCl6ZXRYI+oljvxgky53SZ18qixN4jtvnUOx/UuE3\nYDo0pZMBjk7CX2aKE91tG3kMt0G0LRnHSnkioCTPcDd67pN5myw8oEGHF5PQC9ai\nRZd30V4faCz+kZGO0ilLWGL0EElWILKjgbswgbgwHQYDVR0OBBYEFLvAYj7DJGBy\nMlzxdrwHYrSRPb03MHYGA1UdIwRvMG2AFLvAYj7DJGByMlzxdrwHYrSRPb03oT+k\nPTA7MQswCQYDVQQGEwJVUzEMMAoGA1UECgwDTURMMR4wHAYDVQQDDBVJQUNBIFJv\nb3QgQ2VydGlmaWNhdGWCFEvXsKseN5ulR4j+ZKAnhHdPSTiMMA8GA1UdEwEB/wQF\nMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMEA4GLADCBhwJCAbauH2Uj\noaB7fcKJqBgXqWfSXm5wqo6tEECM4gjtmIKPJnVSBbfcTn2bw7zIl2eBHzRdPX85\nPliPBGxjzyAoQcZ3AkES0U2MiwkDdoyUrb3k3jGOo02ayiCmtfy7y1OVZQWaH2HF\nMgQBbITyFHAZ0HUNpWIT+8527nB7POnJkguMovTIcA==\n-----END CERTIFICATE-----\n';
    const anotherIssuerRootCertificate = fs.readFileSync(`${__dirname}/issuer.pem`, 'utf-8');

    // A test Document Signing Certificate that has been signed by the IACA Root Certificate above
    const issuerDocumentSigningCertificate = '-----BEGIN CERTIFICATE-----\nMIIB1zCCATigAwIBAgIURoTE4I1tg1T7wyVF6YJxJqu2SLgwCgYIKoZIzj0EAwIw\nOzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDEeMBwGA1UEAwwVSUFDQSBSb290\nIENlcnRpZmljYXRlMB4XDTI1MDEyODEyNTU0M1oXDTI2MDEyODEyNTU0M1owQjEL\nMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDElMCMGA1UEAwwcRG9jdW1lbnQgU2ln\nbmluZyBDZXJ0aWZpY2F0ZTAqMAUGAytlcAMhACis1tWdJ2MW+6zokonq9bxhsLO5\nR6E0bFiLnYEWR4t+o0IwQDAdBgNVHQ4EFgQUgxDu5pET///uNotJBKr1gZOZNogw\nHwYDVR0jBBgwFoAUu8BiPsMkYHIyXPF2vAditJE9vTcwCgYIKoZIzj0EAwIDgYwA\nMIGIAkIA4YMSiBuUGrfU1UKeCbYwzp0ZoQhcL+HNCEtgLFW6LtDB4tP+T9A/O5bS\nWV6P+e3mWti13BKCraPRUkKVQA1qyNcCQgFXTRr1Xt+ufVjl1XqnJo0KITN91TyL\n4GKJeBxGYWDFgyvbpCNUs5XeiGejkvhz/8E0fYzCqZmqEIlp6IcvgV8c0A==\n-----END CERTIFICATE-----\n';
    const issuerDocumentSigningKeyPem = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIEQLHY7fwKG6Av4VP3uByNKMyS7/sJKk4ntbzL8nSq0t\n-----END PRIVATE KEY-----\n';
    const issuerDocumentSigningKey = await jose.exportJWK(crypto.createPrivateKey({ key: issuerDocumentSigningKeyPem }));

    const document = new Document('org.iso.18013.5.1.mDL')
      .addIssuerNameSpace('org.iso.18013.5.1', {
        family_name: 'Jones',
        given_name: 'Ava',
        birth_date: '2007-03-25',
      })
      .useDigestAlgorithm('SHA-256')
      .addValidityInfo({
        signed: new Date(),
      })
      .addDeviceKeyInfo({ deviceKey: devicePublicKey });

    const signedDoc = await document.sign({
      issuerPrivateKey: issuerDocumentSigningKey,
      issuerCertificate: issuerDocumentSigningCertificate,
      alg: 'EdDSA',
    });

    const issuerMDoc = new MDoc([signedDoc]).encode();
    const presentationDefinition = {
      id: 'family_name_only',
      input_descriptors: [
        {
          id: 'org.iso.18013.5.1.mDL',
          format: { mso_mdoc: { alg: ['EdDSA', 'ES256'] } },
          constraints: {
            limit_disclosure: 'required',
            fields: [{
              path: ["$['org.iso.18013.5.1']['family_name']"],
              intent_to_retain: false,
            }],
          },
        },
      ],
    };

    const deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
      .usingPresentationDefinition(presentationDefinition)
      .usingSessionTranscriptForOID4VP('', '', '', '')
      .authenticateWithSignature(devicePrivateKey, 'EdDSA')
      .sign();

    const verifier = new Verifier([issuerIacaRootCertificate, anotherIssuerRootCertificate]);
    const diagnosticInfo = await verifier.getDiagnosticInformation(deviceResponseMDoc.encode(), {});

    expect(diagnosticInfo.issuerSignature).toEqual({
      alg: 'EdDSA',
      digests: { 'org.iso.18013.5.1': 3 },
      isValid: true,
      reasons: [],
    });
  });
});
