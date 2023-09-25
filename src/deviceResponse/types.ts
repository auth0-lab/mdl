// eslint-disable-next-line import/no-unresolved
import { Mac0, Sign1 } from 'cose';
import IssuerAuth from './IssuerAuth';
import { IssuerSignedDataItem, IssuerSignedItem } from './IssuerSignedItem';

export type VerificationAssessment = {
  status: 'PASSED' | 'FAILED' | 'WARNING',
  check: string,
  reason?: string,
};

export type OnVerificationAssessmentCallback = (item: VerificationAssessment) => void;

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

export type IssuerSigned = {
  issuerAuth: IssuerAuth;
  nameSpaces: NameSpaces;
};

export type DeviceSignedItems = {
  [x: string]: unknown;
};

export type DeviceAuth =
  | { deviceMac: Mac0 } & { deviceSignature?: never }
  | ({ deviceMac?: never } & { deviceSignature: Sign1 });

export type DeviceSigned = {
  deviceAuth: DeviceAuth;
  nameSpaces: NameSpaces;
};

export type RawIndexedDataItem = IssuerSignedDataItem[];

export type RawNameSpaces = Map<string, RawIndexedDataItem>;

type RawAuthElement = ConstructorParameters<typeof Sign1>;

export type RawIssuerAuth = ConstructorParameters<typeof Sign1>;

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

export type DeviceResponse = {
  documents: MobileDocument[];
  version: string;
  status: number;
  raw: Map<string, any>;
};
