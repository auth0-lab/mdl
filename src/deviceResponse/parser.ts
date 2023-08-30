import { compareVersions } from 'compare-versions';
import { cborDecode } from '../cose/cbor';
import {
  DeviceAuth, DeviceResponse, IssuerAuth, NameSpaces, MobileDocument, RawDeviceAuth, RawIndexedDataItem, RawIssuerAuth, RawNameSpaces,
} from './types';
import CoseSign1 from '../cose/CoseSign1';
import CoseMac0 from '../cose/CoseMac0';
import { IssuerSignedItem } from './IssuerSignedItem';

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
  const { decodedPayload } = issuerAuth;
  const { docType, version } = decodedPayload;

  if (docType !== expectedDocType) {
    throw new MDLParseError(`The issuerAuth docType must be ${expectedDocType}`);
  }

  if (!version || compareVersions(version, '1.0') !== 0) {
    throw new MDLParseError("The issuerAuth version must be '1.0'");
  }

  return issuerAuth;
};

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuth => {
  const { deviceSignature, deviceMac } = Object.fromEntries(rawDeviceAuth);
  if (deviceSignature) {
    return { deviceSignature: new CoseSign1(deviceSignature) };
  }
  return { deviceMac: new CoseMac0(deviceMac) };
};

const namespaceToArray = (namespace: RawIndexedDataItem): IssuerSignedItem[] => {
  return namespace.map((di) => new IssuerSignedItem(di));
};

const unwrapNamespace = (namespace: RawNameSpaces): NameSpaces => {
  return Array.from(namespace.entries()).reduce((prev, [k, entries]) => {
    const mappedNamespace = namespaceToArray(entries);
    return {
      ...prev,
      [k]: mappedNamespace,
    };
  }, {});
};

export const parse = async (
  encodedDeviceResponse: Buffer | Uint8Array,
): Promise<DeviceResponse> => {
  let deviceResponse;
  try {
    deviceResponse = cborDecode(encodedDeviceResponse) as Map<string, any>;
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err.message}`);
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse);

  if (!version) {
    throw new MDLParseError('Device response doesn\'t contain the \'version\' element');
  }

  if (compareVersions(version, '1.0') < 0) {
    throw new MDLParseError(`Device response has an unsupported version: ${version} (expected: >= '1.0')`);
  }

  if (!documents || documents.length === 0) {
    throw new MDLParseError('Device response is invalid since it doesn\'t contain \'documents\' elements');
  }

  const parsedDocuments = documents.map((doc: Map<string, any>): MobileDocument => {
    return {
      raw: doc,
      docType: doc.get('docType'),
      issuerSigned: doc.has('issuerSigned') ? {
        ...doc.get('issuerSigned'),
        nameSpaces: unwrapNamespace(doc.get('issuerSigned').get('nameSpaces')),
        issuerAuth: parseIssuerAuthElement(doc.get('issuerSigned').get('issuerAuth'), doc.get('docType')),
      } : undefined,
      // @ts-ignore
      deviceSigned: doc.has('deviceSigned') ? {
        ...doc.get('deviceSigned'),
        nameSpaces: doc.get('deviceSigned').get('nameSpaces'),
        deviceAuth: parseDeviceAuthElement(doc.get('deviceSigned').get('deviceAuth')),
      } : undefined,
    };
  });

  return {
    documents: parsedDocuments,
    version,
    status,
    raw: deviceResponse,
  };
};
