// eslint-disable-next-line import/no-unresolved
import CoseMac0 from '../cose/CoseMac0';
import CoseSign1 from '../cose/CoseSign1';
import { IssuerSignedDataItem, IssuerSignedItem } from './IssuerSignedItem';

export type VerificationSummaryElement = {
  level: 'error' | 'warn' | 'info',
  msg: string,
};

export type VerificationSummary = Array<VerificationSummaryElement>;

export type ValidityInfo = {
  signed: Date,
  validFrom: Date,
  validUntil: Date,
  expectedUpdate?: Date,
};

export type DSCertificate = {
  validity: {
    notBefore: Date,
    notAfter: Date,
  },
  issuer: {
    countryName: string;
    stateOrProvinceName?: string;
  }
};

export type NameSpaces = {
  [x: string]: IssuerSignedItem[];
};

export type ValidatedIssuerNameSpaces = {
  [x: string]: {
    [x: string]: unknown;
  };
};

export type IssuerAuth = CoseSign1;

export type IssuerSigned = {
  issuerAuth: IssuerAuth;
  nameSpaces: NameSpaces;
};

export type DeviceSignedItems = {
  [x: string]: unknown;
};

export type DeviceAuth =
  | ({ deviceMac: CoseMac0 } & { deviceSignature?: never })
  | ({ deviceMac?: never } & { deviceSignature: CoseSign1 });

export type DeviceSigned = {
  deviceAuth: DeviceAuth;
  nameSpaces: NameSpaces;
};

export type RawIndexedDataItem = IssuerSignedDataItem[];

export type RawNameSpaces = Map<string, RawIndexedDataItem>;

type RawAuthElement = Array<Buffer | Map<number, Buffer>>;

export type RawIssuerAuth = RawAuthElement;

export type RawIssuerSigned = {
  issuerAuth: RawIssuerAuth;
  nameSpaces: RawNameSpaces;
};

export type RawDeviceAuth = Map<'deviceMac' | 'deviceSignature', RawAuthElement>;

export type RawDeviceSigned = {
  deviceAuth: RawDeviceAuth;
  nameSpaces: RawNameSpaces;
};

export type RawMobileDocument = {
  docType: string;
  issuerSigned: RawIssuerSigned;
  deviceSigned: RawDeviceSigned;
};

export type MobileDocument = {
  docType: string;
  raw: Map<string, any>;
  issuerSigned: IssuerSigned;
  deviceSigned: DeviceSigned;
};

export type ParsedDeviceResponse = {
  issuer?: {
    validityInfo?: ValidityInfo,
    nameSpaces?: ValidatedIssuerNameSpaces,
    dsCertificate?: DSCertificate,
  },
  device?: {
    nameSpaces: NameSpaces
  },
  isValid: boolean
};

export type DeviceResponse = {
  documents: MobileDocument[];
  version: string;
  status: number;
  raw: Map<string, any>;
}
