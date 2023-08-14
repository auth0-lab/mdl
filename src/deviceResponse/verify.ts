import { Tagged } from 'cbor';
import { compareVersions } from 'compare-versions';
import { X509Certificate } from '@peculiar/x509';
import CoseSign1 from '../cose/CoseSign1';
import CoseMac0 from '../cose/CoseMac0';
import { cborDecode } from '../cose/cbor';
import { extractX5Chain } from '../cose/headers';
import coseKeyMapToBuffer from '../cose/coseKey';
import { validateDigest, calculateEphemeralMacKey, calculateDeviceAutenticationBytes } from './utils';
import {
  RawMobileDocument,
  RawIssuerAuth,
  RawDeviceAuth,
  RawIssuerNameSpaces,
  IssuerNameSpaces,
  IssuerSignedItem,
  IssuerAuth,
  DeviceAuth,
  DeviceNameSpaces,
  DeviceSignedItems,
  RawDeviceNameSpaces,
  ParsedDeviceResponse,
  DSCertificate,
  MobileDocument,
  ValidatedIssuerNameSpaces,
  ValidityInfo,
} from './types.d';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as { [key: string]: string };

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType: string,
): IssuerAuth => {
  const issuerAuth = new CoseSign1(rawIssuerAuth);
  const { docType, version } = issuerAuth.getDecodedPayload();

  if (docType !== expectedDocType) {
    throw new Error(`issuerAuth's docType must be ${expectedDocType}`);
  }

  if (compareVersions(version, '1.0') !== 0) {
    throw new Error('issuerAuth\'s version must be \'1.0\'');
  }

  return issuerAuth;
};

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuth => {
  if (rawDeviceAuth.deviceSignature) {
    // TODO: this case is not tested yet
    return { deviceSignature: new CoseSign1(rawDeviceAuth.deviceSignature) };
  }

  return { deviceMac: new CoseMac0(rawDeviceAuth.deviceMac) };
};

const parseIssuerNameSpaces = (rawIssuerNameSpaces: RawIssuerNameSpaces): IssuerNameSpaces => {
  const nameSpaces: IssuerNameSpaces = {};

  Object.keys(rawIssuerNameSpaces).forEach((ns) => {
    nameSpaces[ns] = rawIssuerNameSpaces[ns].map(
      (t) => cborDecode(t.value) as IssuerSignedItem,
    );
  });

  return nameSpaces;
};

const parseDeviceNameSpaces = (rawDeviceNameSpaces: RawDeviceNameSpaces): DeviceNameSpaces => {
  const nameSpaces: DeviceNameSpaces = {};

  if (rawDeviceNameSpaces instanceof Tagged) {
    return cborDecode(rawDeviceNameSpaces.value) as DeviceNameSpaces;
  }

  Object.keys(rawDeviceNameSpaces).forEach((ns) => {
    nameSpaces[ns] = cborDecode(rawDeviceNameSpaces[ns].value) as DeviceSignedItems;
  });

  return nameSpaces;
};

const verifyIssuerSignature = async (msg: IssuerAuth):
  Promise<{ validityInfo: ValidityInfo, dsCertificate: DSCertificate }> => {
  // Confirm that the mdoc data is issued by the issuing authority
  // TODO: validate alg (expected: CoseSignAlgorithm.ECDS_256)

  // Parse issuer certificate
  // TODO: validate cert root authority
  const rawIssuerCert = extractX5Chain(msg);
  // TODO: validate x5c
  const issuerCert = new X509Certificate(rawIssuerCert);
  const verificationResult = await msg.verify(issuerCert.publicKey.rawData);
  if (!verificationResult) {
    throw new Error('issuerAuth signature is tempered');
  }

  // Validity
  const { validityInfo } = msg.getDecodedPayload();
  const now = new Date();
  if (validityInfo.signed < issuerCert.notBefore && validityInfo.signed > issuerCert.notAfter) {
    throw new Error(`The MSO signed date (${validityInfo.signed}) is not within the validity period of the certificate (${issuerCert.notBefore} to ${issuerCert.notAfter})`);
  }

  if (now < validityInfo.validFrom) {
    throw new Error(`The MSO is not valid until ${validityInfo.validFrom}`);
  }

  if (validityInfo.validUntil < now) {
    throw new Error(`The MSO was expired at ${validityInfo.validUntil}`);
  }

  // countryName is mandatory, stateOrProvinceName is optional
  const stateOrProvinceName = issuerCert.issuerName.getField('ST')[0];
  const countryName = issuerCert.issuerName.getField('C')[0];
  if (!countryName) {
    throw new Error('Country name (C) not found in the issuer certificate\'s subject distinguished name.');
  }

  return { validityInfo, dsCertificate: { countryName, stateOrProvinceName } };
};

const verifyDeviceSignature = async (
  deviceAuth: DeviceAuth,
  options: {
    deviceKeyCoseKey: Map<number, Buffer | number>;
    ephemeralPrivateKey: Buffer;
    sessionTranscriptBytes: Buffer;
    docType: string;
    nameSpaces: RawDeviceNameSpaces;
  },
) => {
  // Prevent cloning of the mdoc and mitigate man in the middle attacks.
  const deviceKey = coseKeyMapToBuffer(options.deviceKeyCoseKey);
  const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
    options.sessionTranscriptBytes,
    options.docType,
    options.nameSpaces,
  );

  if (deviceAuth.deviceSignature) {
    // ECDSA/EdDSA authentication
    // TODO: this case is not tested yet
    // TODO: validate alg (expected: CoseSignAlgorithm.ECDS_256)
    const verificationResult = await deviceAuth.deviceSignature.verify(
      deviceKey,
      deviceAuthenticationBytes,
    );
    if (!verificationResult) {
      throw new Error('deviceAuth.deviceSignature is tempered');
    }
    return;
  }

  // MAC authentication
  const { deviceMac } = deviceAuth;
  if (!deviceMac) {
    throw new Error('deviceAuth element does not contain a deviceSignature or deviceMac element');
  }

  // TODO: validate alg (expected: CoseMacAlgorithm.HMAC_256_256)
  const ephemeralMacKey = calculateEphemeralMacKey(
    deviceKey,
    options.ephemeralPrivateKey,
    options.sessionTranscriptBytes,
  );

  const expectedMac = await CoseMac0.generate(
    ephemeralMacKey,
    Buffer.alloc(0),
    deviceAuthenticationBytes,
  );

  if (expectedMac.getTag().compare(deviceMac.getTag()) !== 0) {
    throw new Error('Device MAC mismatch');
  }
};

const verifyData = (mdoc: MobileDocument, dsCertificate: DSCertificate): {
  issuerNameSpaces: ValidatedIssuerNameSpaces, deviceNameSpaces: DeviceNameSpaces
} => {
  // Confirm that the mdoc data has not changed since issuance.
  const { issuerAuth } = mdoc.issuerSigned;
  const { valueDigests, digestAlgorithm } = cborDecode(
    issuerAuth.getPayload(),
  ) as { valueDigests: { [x: string]: Map<number, Buffer> }, digestAlgorithm: string };
  const nameSpaces = mdoc.issuerSigned.nameSpaces || {};

  const issuerNameSpaces = {} as ValidatedIssuerNameSpaces;

  Object.keys(nameSpaces).forEach((ns) => {
    const digests = valueDigests[ns];
    if (!digests) {
      throw new Error(`Unable to find digests for namespace: ${ns}`);
    }

    if (!DIGEST_ALGS[digestAlgorithm]) {
      throw new Error(
        `Unsupported digest algorithm: ${digestAlgorithm}. Expected one of these algorithms: ${Object.keys(
          DIGEST_ALGS,
        ).join(', ')}`,
      );
    }

    issuerNameSpaces[ns] = {};

    nameSpaces[ns].forEach((ev, i) => {
      validateDigest(
        DIGEST_ALGS[digestAlgorithm],
        digests.get(ev.digestID),
        mdoc.raw.issuerSigned.nameSpaces[ns][i],
        ns,
        ev.elementIdentifier,
      );
      issuerNameSpaces[ns][ev.elementIdentifier] = ev.elementValue;
    });

    if (ns === MDL_NAMESPACE) {
      // if the `issuing_country` was retrieved, verify that the value matches the `countryName`
      // in the subject field within the DS certificate
      if (issuerNameSpaces[ns].issuing_country
        && issuerNameSpaces[ns].issuing_country !== dsCertificate.countryName) {
        throw new Error(`The 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) must match the 'countryName' (${dsCertificate.countryName}) in the subject field within the DS certificate`);
      }

      // if the `issuing_jurisdiction` was retrieved, and `stateOrProvinceName` is
      // present in the subject field within the DS certificate, they must have the same value
      if (issuerNameSpaces[ns].issuing_jurisdiction
        && dsCertificate.stateOrProvinceName
        && issuerNameSpaces[ns].issuing_jurisdiction !== dsCertificate.stateOrProvinceName) {
        throw new Error(`The 'issuing_jurisdiction' (${issuerNameSpaces[ns].issuing_jurisdiction}) must match the 'stateOrProvinceName' (${dsCertificate.stateOrProvinceName}) in the subject field within the DS certificate`);
      }
    }
  });

  return { issuerNameSpaces, deviceNameSpaces: mdoc.deviceSigned.nameSpaces };
};

/**
 * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
 *
 * @param encodedDeviceResponse
 * @param options.encodedSessionTranscript The CBOR encoded SessionTranscript.
 * @param options.ephemeralReaderKey The private part of the ephemeral key used in the session where
 * the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC
 * method for device authentication.
 */
export default async (
  encodedDeviceResponse: Buffer,
  options: { encodedSessionTranscript: Buffer, ephemeralReaderKey?: Buffer },
): Promise<ParsedDeviceResponse> => {
  const deviceResponse = cborDecode(encodedDeviceResponse, { skipExtraTags: true }) as {
    version: string,
    documents: Array<unknown>
  };

  if (!deviceResponse.version) {
    throw new Error('The device response is invalid since it doesn\'t contain the \'version\' element.');
  }

  if (!deviceResponse.documents) {
    throw new Error('The device response is invalid since it doesn\'t contain the \'documents\' element.');
  }

  if (compareVersions(deviceResponse.version, '1.0') < 0) {
    throw new Error(`The device response has an unsupported version: ${deviceResponse.version} (expected: >= '1.0')`);
  }

  const mdoc = deviceResponse.documents.map((doc: RawMobileDocument) => ({
    docType: doc.docType,
    raw: doc,
    issuerSigned: {
      issuerAuth: parseIssuerAuthElement(doc.issuerSigned.issuerAuth, doc.docType),
      nameSpaces: parseIssuerNameSpaces(doc.issuerSigned.nameSpaces),
    },
    deviceSigned: {
      deviceAuth: parseDeviceAuthElement(doc.deviceSigned.deviceAuth),
      nameSpaces: parseDeviceNameSpaces(doc.deviceSigned.nameSpaces),
    },
  }));

  // TODO: support multiple docs
  const { issuerAuth } = mdoc[0].issuerSigned;
  const { deviceKey } = issuerAuth.getDecodedPayload().deviceKeyInfo;

  const { validityInfo, dsCertificate } = await verifyIssuerSignature(issuerAuth);
  await verifyDeviceSignature(mdoc[0].deviceSigned.deviceAuth as DeviceAuth, {
    deviceKeyCoseKey: deviceKey as Map<number, Buffer | number>,
    ephemeralPrivateKey: options.ephemeralReaderKey,
    sessionTranscriptBytes: options.encodedSessionTranscript,
    docType: mdoc[0].docType,
    nameSpaces: mdoc[0].raw.deviceSigned.nameSpaces,
  });

  const { issuerNameSpaces, deviceNameSpaces } = verifyData(mdoc[0], dsCertificate);

  return {
    issuer: { validityInfo, nameSpaces: issuerNameSpaces, dsCertificate },
    device: { nameSpaces: deviceNameSpaces },
  };
};
