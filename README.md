# mDL

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver Licenses): an ISO standard for digital driver licenses.

This is a Node.js library to issue and verify mDL [CBOR encoded](https://cbor.io/) documents in accordance with **ISO 18013-7 (draft's date: 2024-02-13)**.

> If you are working with the **2023 draft** make sure to use the `@auth0/mdl@v1` version.

## Installation

```bash
npm i @auth0/mdl
```

## Verifying a credential

```javascript
import { Verifier } from "@auth0/mdl";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
  const encodedDeviceResponse = Buffer.from(encodedDeviceResponseHex, 'hex');
  const encodedSessionTranscript = Buffer.from(encodedSessionTranscriptHex, 'hex');
  const ephemeralReaderKey = Buffer.from(ephemeralReaderKeyHex, 'hex');

  const trustedCerts = [fs.readFileSync('./caCert1.pem')/*, ... */];
  const verifier = new Verifier(trustedCerts);

  let mdoc;

  /** ... using OID4VP protocol (Annex B): */
  {
    mdoc = await verifier
      .usingEphemeralReaderKey(ephemeralReaderKey)
      .usingSessionTranscriptForOID4VP(
        mdocGeneratedNonce,    //
        clientId,              // Parameters coming from
        responseUri,           // the OID4VP transaction
        verifierGeneratedNonce  //
      )
      .verify(encodedDeviceResponse);
  }

  /** ... OR ALTERNATIVELY using the Web API protocol (Annex A): */
  {
    mdoc = await verifier
      .usingEphemeralReaderKey(ephemeralReaderKey)
      .usingSessionTranscriptForWebAPI(
        encodedDeviceEngagement, // CBOR as received from the reader
        encodedReaderEngagement, // CBOR as sent to the reader
        encodedReaderPublicKey,  // as found in the ReaderEngagement
      )
      .verify(encodedDeviceResponse);
  }

  //at this point the issuer and device signature are valid.
  inspect(mdoc);
})();
```

## Getting diagnostic information

```javascript
import { Verifier } from "@auth0/mdl";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
  const encodedDeviceResponse = Buffer.from(encodedDeviceResponseHex, 'hex');
  const encodedSessionTranscript = Buffer.from(encodedSessionTranscriptHex, 'hex');
  const ephemeralReaderKey = Buffer.from(ephemeralReaderKeyHex, 'hex');

  const trustedCerts = [fs.readFileSync('./caCert1.pem')/*, ... */];
  const verifier = new Verifier(trustedCerts);

  let diagnosticInfo;
  
    /** ... using OID4VP protocol (Annex B): */
  {
    mdoc = await verifier
      .usingEphemeralReaderKey(ephemeralReaderKey)
      .usingSessionTranscriptForOID4VP(
        mdocGeneratedNonce,    //
        clientId,              // Parameters coming from
        responseUri,           // the OID4VP transaction
        verifierGeneratedNonce  //
      )
      .getDiagnosticInformation(encodedDeviceResponse);
  }

  /** ... OR ALTERNATIVELY using the Web API protocol (Annex A): */
  {
    mdoc = await verifier
      .usingEphemeralReaderKey(ephemeralReaderKey)
      .usingSessionTranscriptForWebAPI(
        encodedDeviceEngagement, // CBOR as received from the reader
        encodedReaderEngagement, // CBOR as sent to the reader
        encodedReaderPublicKey,  // as found in the ReaderEngagement
      )
      .getDiagnosticInformation(encodedDeviceResponse);
  }

  inspect(diagnosticInfo);
})();
```

## Issuing a credential

```js
import { MDoc, Document } from "@auth0/mdl";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
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
    .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
    .sign({
      issuerPrivateKey,
      issuerCertificate,
    });

  const mdoc = new MDoc([document]).encode();

  inspect(encoded);
})();
```

## Generating a device response

```js
import { DeviceResponse, DataItem, MDoc, DataItem, cborEncode} from '@auth0/mdl';
import { createHash } from 'node:crypto';

(async () => {
  let issuerMDoc;
  let deviceResponseMDoc;

  /**
   * This is what the MDL issuer does to generate a credential:
   */
  {
    let issuerPrivateKey;
    let issuerCertificate;
    let devicePublicKey; // the public key for the device, as a JWK
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
      .addDeviceKeyInfo({ deviceKey: devicePublicKey })
      .sign({
        issuerPrivateKey,
        issuerCertificate,
        alg: 'ES256',
      });
    issuerMDoc = new MDoc([document]).encode();
  }

  /**
   * This is what the DEVICE does to generate a response...
   */
  {
    let devicePrivateKey; // the private key for the device, as a JWK
    let presentationDefinition = {
      // the presentation definition we create a response for
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

    /** ... using OID4VP protocol (Annex B): */
    {
      deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
        .usingPresentationDefinition(presentationDefinition)
        .usingSessionTranscriptForOID4VP(
          mdocGeneratedNonce,    //
          clientId,              // Parameters coming from
          responseUri,           // the OID4VP transaction
          verifierGeneratedNonce  //
        )
        .authenticateWithSignature(devicePrivateKey, 'ES256')
        .sign();
    }

    /** ... OR ALTERNATIVELY using the Web API protocol (Annex A): */
    {
      deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
        .usingPresentationDefinition(presentationDefinition)
        .usingSessionTranscriptForWebAPI(
          encodedDeviceEngagement, // CBOR as received from the reader
          encodedReaderEngagement, // CBOR as sent to the reader
          encodedReaderPublicKey,  // as found in the ReaderEngagement
        )
        .authenticateWithSignature(devicePrivateKey, 'ES256')
        .sign();
    }
  }
})();
```

## License

Apache-2.0
