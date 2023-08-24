// import { cborDecode } from "../cose/cbor";
import { cborDecode } from "../cose/cbor2";
import { compareVersions } from 'compare-versions';
import { DeviceAuth, IssuerAuth, MobileDocument, RawDeviceAuth, RawIssuerAuth, RawMobileDocument } from "./types";
import CoseSign1 from "../cose/CoseSign1";
import CoseMac0 from "../cose/CoseMac0";

export class MDLParseError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType: string,
): IssuerAuth => {
  const issuerAuth = new CoseSign1(rawIssuerAuth);
  const { docType, version } = issuerAuth.getDecodedPayload();

  if (docType !== expectedDocType) {
    throw new MDLParseError(`The issuerAuth docType must be ${expectedDocType}`);
  }

  if (!version || compareVersions(version, '1.0') !== 0) {
    throw new MDLParseError(`The issuerAuth version must be '1.0'`);
  }

  return issuerAuth;
};

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuth => {
  if (rawDeviceAuth.deviceSignature) {
    return { deviceSignature: new CoseSign1(rawDeviceAuth.deviceSignature) };
  }
  return { deviceMac: new CoseMac0(rawDeviceAuth.deviceMac) };
};


export const parse = async (
  encodedDeviceResponse: Buffer,
): Promise<MobileDocument[]> => {
  let deviceResponse;
  try {
    deviceResponse = cborDecode(encodedDeviceResponse) as {
      version: string,
      documents: Array<unknown>
    };
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err.message}`);
  }

  if (!deviceResponse.version) {
    throw new MDLParseError(`Device response doesn't contain the 'version' element`);
  }

  if (compareVersions(deviceResponse.version, '1.0') < 0) {
    throw new MDLParseError(`Device response has an unsupported version: ${deviceResponse.version} (expected: >= '1.0')`);
  }

  if (!deviceResponse.documents || deviceResponse.documents.length === 0) {
    throw new MDLParseError(`Device response is invalid since it doesn't contain 'documents' elements`);
  }

  return deviceResponse.documents.map((doc: RawMobileDocument): MobileDocument => ({
    docType: doc.docType,
    raw: doc,
    issuerSigned: {
      ...doc.issuerSigned,
      issuerAuth: parseIssuerAuthElement(doc.issuerSigned.issuerAuth, doc.docType),
    },
    deviceSigned: doc.deviceSigned ? {
      ...doc.deviceSigned,
      deviceAuth: parseDeviceAuthElement(doc.deviceSigned.deviceAuth),
    } : undefined,
  }));
};
