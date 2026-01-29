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
    const issuerIacaRootCertificate = '-----BEGIN CERTIFICATE-----\nMIICuzCCAh2gAwIBAgIUdHlMcv60FPe56XKGczufsRweUg0wCgYIKoZIzj0EAwQw\nOzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDEeMBwGA1UEAwwVSUFDQSBSb290\nIENlcnRpZmljYXRlMB4XDTI2MDEyOTE0MzYzNloXDTM2MDEyNzE0MzYzNlowOzEL\nMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDEeMBwGA1UEAwwVSUFDQSBSb290IENl\ncnRpZmljYXRlMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAbUCSRD2grKArOgQP\n4YtqHu09RBZGpZEYMGUkcarrtD3DWTzhR+OJAYjFw1WNKdoBA//wxnYWJz61emm6\nlXxDvE4AMz2iIOvGfIYkwhfdxY1vWmvgHYjouknZR049PhoXjbfcUAhuT0ySY01+\nxIZOR4+BD0/sbOY4//RxioLKmfxSiGyjgbswgbgwHQYDVR0OBBYEFCDj4veEFyaV\nfdQ6opfym2T+1dTUMHYGA1UdIwRvMG2AFCDj4veEFyaVfdQ6opfym2T+1dTUoT+k\nPTA7MQswCQYDVQQGEwJVUzEMMAoGA1UECgwDTURMMR4wHAYDVQQDDBVJQUNBIFJv\nb3QgQ2VydGlmaWNhdGWCFHR5THL+tBT3uelyhnM7n7EcHlINMA8GA1UdEwEB/wQF\nMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMEA4GLADCBhwJBU5V4OJvj\np/xsHZ5CBjf6m7tVopfcbpa0fUEIZuO+UAORcIu2iDkBPc5MWVrLib9gHSfzKYza\nvx16LW89X06PKVoCQgHgeb4SY2vE4mSNDAiJuCJcQpcluJcqkzzsFXr+UEgXCn0m\nkQiErhZI/VIDDANboxp4SC18G05wgZrR0Rt/lj+JgA==\n-----END CERTIFICATE-----\n';
    const anotherIssuerRootCertificate = fs.readFileSync(`${__dirname}/issuer.pem`, 'utf-8');

    // A test Document Signing Certificate that has been signed by the IACA Root Certificate above
    const issuerDocumentSigningCertificate = '-----BEGIN CERTIFICATE-----\nMIIB1jCCATigAwIBAgIUUhuDtxv9ZZi0WoYTu6sMcQTJpMMwCgYIKoZIzj0EAwIw\nOzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDEeMBwGA1UEAwwVSUFDQSBSb290\nIENlcnRpZmljYXRlMB4XDTI2MDEyOTE0MzY1NFoXDTI4MTAyNTE0MzY1NFowQjEL\nMAkGA1UEBhMCVVMxDDAKBgNVBAoMA01ETDElMCMGA1UEAwwcRG9jdW1lbnQgU2ln\nbmluZyBDZXJ0aWZpY2F0ZTAqMAUGAytlcAMhAHComhACeh4mfkmpFEd+TO9h8Pl+\n9davZg3Z2oBcxZsMo0IwQDAdBgNVHQ4EFgQUCyFo7Jc9jDdWXP2bnZZJ2DfNhd0w\nHwYDVR0jBBgwFoAUIOPi94QXJpV91Dqil/KbZP7V1NQwCgYIKoZIzj0EAwIDgYsA\nMIGHAkFsNebOzVH3deWo6VwCA2aGWdkMtKgNCcYNLXS++gh9o3mc2iNAo0WGiARA\nGgF6QxZMZiuPeCyHwXLbd8BZ71FM1QJCAJ7aSD9CAhjbdloaAIOzjkM1gOYc7pTD\nIbITatQc29mlZTkUJtf9/UO+uaWqkme8Pv1phPX9VKJm4rkpCQHIygzS\n-----END CERTIFICATE-----\n';
    const issuerDocumentSigningKeyPem = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIE0IafyGBVPyT7m4cfwPEoQ/5rZJrbuwuqFn5ZTmYIW/\n-----END PRIVATE KEY-----\n';
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
