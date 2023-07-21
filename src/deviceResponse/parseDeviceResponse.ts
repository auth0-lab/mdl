import { Tagged } from 'cbor';
import { compareVersions } from 'compare-versions';
import CoseSign1 from '../cose/CoseSign1';
import CoseMac0 from '../cose/CoseMac0';
import { cborDecode } from '../cose/cbor';
import {
  RawMobileDocument,
  RawIssuerAuth,
  RawDeviceAuth,
  RawIssuerNameSpaces,
  IssuerNameSpaces,
  IssuerSignedItem,
  DeviceAuth,
  DeviceNameSpaces,
  DeviceSignedItems,
  RawDeviceNameSpaces,
  ParsedDeviceResponse,
} from './deviceResponse';
import { verifyDeviceSignature, verifyIssuerSignature } from './verifySignature';
import verifyData from './verifyData';

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType: string,
): CoseSign1 => {
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

// TODO: this function is not fully tested yet
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

/**
 * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
 *
 * @param deviceResponse - The hexadecimal representation of the device response.
 */
const parseDeviceResponse = async (
  encodedDeviceResponse: string,
  options: { ephemeralPrivateKey: Buffer, sessionTranscriptBytes: Buffer },
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
  const { validityInfo, dsCertificate } = await verifyIssuerSignature(issuerAuth as CoseSign1);
  await verifyDeviceSignature(mdoc[0].deviceSigned.deviceAuth as DeviceAuth, {
    deviceKeyCoseKey: deviceKey as Map<number, Buffer | number>,
    ephemeralPrivateKey: options.ephemeralPrivateKey,
    sessionTranscriptBytes: options.sessionTranscriptBytes,
    docType: mdoc[0].docType,
    nameSpaces: mdoc[0].raw.deviceSigned.nameSpaces,
  });

  const { issuerNameSpaces, deviceNameSpaces } = verifyData(mdoc[0], dsCertificate);

  return {
    issuer: { validityInfo, nameSpaces: issuerNameSpaces, dsCertificate },
    device: { nameSpaces: deviceNameSpaces },
  };
};

export default parseDeviceResponse;
