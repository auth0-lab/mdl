# mDL

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver Licenses): an ISO standard for digital driver licenses.

This is a Node.js library to issue and verify mDL [CBOR encoded](https://cbor.io/) documents.

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
  const mdoc = await verifier.verify(encodedDeviceResponse, {
    ephemeralReaderKey,
    encodedSessionTranscript,
  });

  //at this point the issuer and device signature are valids.
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

  const diagnosticInfo = await verifier.getDiagnosticInformation(encodedDeviceResponse, {
    ephemeralReaderKey,
    encodedSessionTranscript,
  });

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
    .addDeviceKeyInfo({ devicePublicKey: publicKeyJWK })
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
import { DeviceResponse } from "@auth0/mdl";
(() => {
  let issuerMDoc;
  let deviceResponseMDoc;
  // this is what the MDL issuer does to generate a credential:
  {
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
        issuerCertificate,
      });
    issuerMDoc = new MDoc([document]).encode();
  }

  //This is what the DEVICE does to generate a response
  {
    deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
      .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
      .usingHandover([mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce])
      .authenticateWithSignature(devicePrivateKey)
      .generate();
  }
})();
```

## License

Apache-2.0
