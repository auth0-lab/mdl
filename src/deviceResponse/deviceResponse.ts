// eslint-disable-next-line import/no-unresolved
import Tagged from 'cbor/types/lib/tagged';
import CoseMac0 from '../cose/CoseMac0';
import CoseSign1 from '../cose/CoseSign1';

export type ValidityInfo = {
  signed: Date,
  validFrom: Date,
  validUntil: Date,
  expectedUpdate?: Date,
};

export type IssuerSignedItem = {
  digestID: number;
  random: Buffer;
  elementIdentifier: string;
  elementValue: unknown;
};

export type IssuerNameSpaces = {
  [x: string]: Array<IssuerSignedItem>;
};

export type ValidatedIssuerNameSpaces = {
  [x: string]: {
    [x: string]: unknown;
  };
};

export type IssuerSigned = {
  issuerAuth: CoseSign1;
  nameSpaces: IssuerNameSpaces;
};

export type DeviceSignedItems = {
  [x: string]: unknown;
};

export type DeviceNameSpaces = {
  [x: string]: DeviceSignedItems;
};

export type DeviceAuth =
  | ({ deviceMac: CoseMac0 } & { deviceSignature?: never })
  | ({ deviceMac?: never } & { deviceSignature: CoseSign1 });

export type DeviceSigned = {
  deviceAuth: DeviceAuth;
  nameSpaces: DeviceNameSpaces;
};

export type RawIssuerNameSpace = Array<Tagged>;

export type RawIssuerNameSpaces = {
  [key: string]: RawIssuerNameSpace;
};

export type RawDeviceNameSpace = Tagged;

export type RawDeviceNameSpaces = {
  [key: string]: RawDeviceNameSpace;
};

type RawAuthElement = Array<Buffer | Map<number, Buffer>>;

export type RawIssuerAuth = RawAuthElement;

export type RawIssuerSigned = {
  issuerAuth: RawIssuerAuth;
  nameSpaces: RawIssuerNameSpaces;
};

export type RawDeviceAuth =
  | ({ deviceMac: RawAuthElement } & { deviceSignature?: never })
  | ({ deviceMac?: never } & { deviceSignature: RawAuthElement });

export type RawDeviceSigned = {
  deviceAuth: RawDeviceAuth;
  nameSpaces: RawDeviceNameSpaces;
};

export type RawMobileDocument = {
  docType: string;
  issuerSigned: RawIssuerSigned;
  deviceSigned: RawDeviceSigned;
};

export type MobileDocument = {
  docType: string;
  raw: RawMobileDocument;
  issuerSigned: IssuerSigned;
  deviceSigned: DeviceSigned;
};

export type ParsedDeviceResponse = {
  issuer: {
    validityInfo: ValidityInfo,
    nameSpaces: ValidatedIssuerNameSpaces
  },
  device: {
    nameSpaces: DeviceNameSpaces
  }
};
