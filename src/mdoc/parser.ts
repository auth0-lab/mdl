import { compareVersions } from 'compare-versions';
import { Mac0, Sign1 } from 'cose-kit';
import { cborDecode } from '../cbor';
import {
  DeviceAuth, MDoc, IssuerNameSpaces, MobileDocument, RawDeviceAuth, RawIndexedDataItem, RawIssuerAuth, RawNameSpaces,
} from './types';
import IssuerAuth from './IssuerAuth';
import { IssuerSignedItem } from './IssuerSignedItem';
import { MDLParseError } from './errors';

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType: string,
): IssuerAuth => {
  const issuerAuth = new IssuerAuth(...rawIssuerAuth);
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
    return { deviceSignature: new Sign1(...deviceSignature) };
  }
  return { deviceMac: new Mac0(...deviceMac) };
};

const namespaceToArray = (
  issuerAuth: IssuerAuth,
  nameSpace: string,
  entries: RawIndexedDataItem,
): IssuerSignedItem[] => {
  return entries.map((di) => new IssuerSignedItem(issuerAuth, nameSpace, di));
};

const unwrapNamespace = (issuerAuth: IssuerAuth, namespace: RawNameSpaces): IssuerNameSpaces => {
  return Array.from(namespace.entries()).reduce((prev, [nameSpace, entries]) => {
    const mappedNamespace = namespaceToArray(issuerAuth, nameSpace, entries);
    return {
      ...prev,
      [nameSpace]: mappedNamespace,
    };
  }, {});
};

/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
export const parse = async (
  encoded: Buffer | Uint8Array,
): Promise<MDoc> => {
  let deviceResponse;
  try {
    deviceResponse = cborDecode(encoded) as Map<string, any>;
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err.message}`);
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse);

  const parsedDocuments = documents.map((doc: Map<string, any>): MobileDocument => {
    const issuerAuth = parseIssuerAuthElement(
      doc.get('issuerSigned').get('issuerAuth'),
      doc.get('docType'),
    );
    return {
      raw: doc,
      docType: doc.get('docType'),
      issuerSigned: doc.has('issuerSigned') ? {
        ...doc.get('issuerSigned'),
        nameSpaces: unwrapNamespace(
          issuerAuth,
          doc.get('issuerSigned').get('nameSpaces'),
        ),
        issuerAuth,
      } : undefined,
      // @ts-ignore
      deviceSigned: doc.has('deviceSigned') ? {
        ...doc.get('deviceSigned'),
        nameSpaces: doc.get('deviceSigned').get('nameSpaces').data,
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
