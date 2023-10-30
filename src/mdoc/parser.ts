import { compareVersions } from 'compare-versions';
import { Mac0, Sign1 } from 'cose-kit';
import { cborDecode } from '../cbor';
import { MDoc } from './model/MDoc';
import {
  DeviceAuth, IssuerNameSpaces, RawDeviceAuth, RawIndexedDataItem, RawIssuerAuth, RawNameSpaces,
} from './model/types';
import IssuerAuth from './model/IssuerAuth';
import { IssuerSignedItem } from './IssuerSignedItem';
import { MDLParseError } from './errors';
import { DeviceSignedDocument, IssuerSignedDocument } from './model/IssuerSignedDocument';

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
  entries: RawIndexedDataItem,
): IssuerSignedItem[] => {
  return entries.map((di) => new IssuerSignedItem(di));
};

const mapIssuerNameSpaces = (namespace: RawNameSpaces): IssuerNameSpaces => {
  return Array.from(namespace.entries()).reduce((prev, [nameSpace, entries]) => {
    const mappedNamespace = namespaceToArray(entries);
    return {
      ...prev,
      [nameSpace]: mappedNamespace,
    };
  }, {});
};

const mapDeviceNameSpaces = (namespace: Map<string, Map<string, any>>) => {
  const entries = Array.from(namespace.entries()).map(([ns, attrs]) => {
    return [ns, Object.fromEntries(attrs.entries())];
  });
  return Object.fromEntries(entries);
};

/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
export const parse = (
  encoded: Buffer | Uint8Array,
): MDoc => {
  let deviceResponse;
  try {
    deviceResponse = cborDecode(encoded) as Map<string, any>;
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err.message}`);
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse);

  const parsedDocuments: IssuerSignedDocument[] = documents.map((doc: Map<string, any>): IssuerSignedDocument => {
    const issuerAuth = parseIssuerAuthElement(
      doc.get('issuerSigned').get('issuerAuth'),
      doc.get('docType'),
    );

    const issuerSigned = doc.has('issuerSigned') ? {
      ...doc.get('issuerSigned'),
      nameSpaces: mapIssuerNameSpaces(
        doc.get('issuerSigned').get('nameSpaces'),
      ),
      issuerAuth,
    } : undefined;

    const deviceSigned = doc.has('deviceSigned') ? {
      ...doc.get('deviceSigned'),
      nameSpaces: mapDeviceNameSpaces(doc.get('deviceSigned').get('nameSpaces').data),
      deviceAuth: parseDeviceAuthElement(doc.get('deviceSigned').get('deviceAuth')),
    } : undefined;

    if (deviceSigned) {
      return new DeviceSignedDocument(
        doc.get('docType'),
        issuerSigned,
        deviceSigned,
      );
    }
    return new IssuerSignedDocument(
      doc.get('docType'),
      issuerSigned,
    );
  });

  return new MDoc(parsedDocuments, version, status);
};
