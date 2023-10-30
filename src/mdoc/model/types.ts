// eslint-disable-next-line import/no-unresolved
import { Mac0, Sign1 } from 'cose-kit';
import { JWK } from 'jose';
import IssuerAuth from './IssuerAuth';
import { IssuerSignedDataItem, IssuerSignedItem } from '../IssuerSignedItem';

export type ValidityInfo = {
  signed: Date,
  validFrom: Date,
  validUntil: Date,
  expectedUpdate?: Date,
};

export type IssuerNameSpaces = {
  [x: string]: IssuerSignedItem[];
};

export type ValidatedIssuerNameSpaces = {
  [x: string]: {
    [x: string]: unknown;
  };
};

export type IssuerSigned = {
  issuerAuth: IssuerAuth;
  nameSpaces: IssuerNameSpaces;
};

export type DeviceAuth =
  | { deviceMac: Mac0 } & { deviceSignature?: never }
  | ({ deviceMac?: never } & { deviceSignature: Sign1 });

export type DeviceSigned = {
  deviceAuth: DeviceAuth;
  nameSpaces: Record<string, Record<string, any>>;
};

export type RawIndexedDataItem = IssuerSignedDataItem[];

export type RawNameSpaces = Map<string, RawIndexedDataItem>;

type RawAuthElement = ConstructorParameters<typeof Sign1>;

export type RawIssuerAuth = ConstructorParameters<typeof Sign1>;

export type RawDeviceAuth = Map<'deviceMac' | 'deviceSignature', RawAuthElement>;

export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

export type DiagnosticInformation = {
  general: {
    type: string,
    version: string,
    status: number,
    documents: number,
  },
  validityInfo: ValidityInfo,
  attributes: {
    ns: string,
    id: string,
    value: any,
    isValid: boolean,
    matchCertificate?: boolean,
  }[],
  deviceAttributes: {
    ns: string,
    id: string,
    value: any,
  }[],
  issuerCertificate?: {
    subjectName: string;
    notBefore: Date;
    notAfter: Date;
    serialNumber: string;
    thumbprint: string;
    pem: string;
  },
  issuerSignature: {
    alg: string,
    isValid: boolean;
    reasons?: string[];
    digests: {
      [ns: string]: number;
    };
  },
  deviceKey: {
    jwk: JWK;
  },
  deviceSignature: {
    alg: string;
    isValid: boolean;
    reasons?: string[];
  }
  dataIntegrity: {
    disclosedAttributes: string;
    isValid: boolean;
    reasons?: string[];
  }
};

export type MSO = {
  digestAlgorithm: DigestAlgorithm;
  docType: string;
  version: string;

  validityInfo: ValidityInfo;

  valueDigests?: Map<string, Map<number, Uint8Array>>;

  validityDigests?: {
    [key: string]: Map<number, Uint8Array>;
  };

  deviceKeyInfo?: {
    deviceKey: Map<number, number | Uint8Array>;
    [key: string]: any;
  };
};

export type DocType = 'org.iso.18013.5.1.mDL';

export type SupportedAlgs = 'ES256' | 'ES384' | 'ES512' | 'EdDSA';
