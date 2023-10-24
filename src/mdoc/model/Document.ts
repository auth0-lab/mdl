import * as jose from 'jose';
import { COSEKeyFromJWK, ProtectedHeader, UnprotectedHeaders } from 'cose-kit';
import { fromPEM } from '../utils';
import { DataItem, cborEncode } from '../../cbor';
import { IssuerSignedItem } from '../IssuerSignedItem';
import IssuerAuth from './IssuerAuth';
import { DeviceSigned, DigestAlgorithm, IssuerNameSpaces, IssuerSigned, MSO, ValidityInfo } from './types';

const DEFAULT_NS = 'org.iso.18013.5.1';

const getAgeInYears = (birth: string): number => {
  const birthDate = new Date(birth);
  birthDate.setHours(0, 0, 0, 0);
  // @ts-ignore
  const ageDifMs = Date.now() - birthDate;
  const ageDate = new Date(ageDifMs);
  return Math.abs(ageDate.getUTCFullYear() - 1970);
};

const addYears = (date: Date, years: number): Date => {
  const r = new Date(date.getTime());
  r.setFullYear(date.getFullYear() + years);
  return r;
};

export type DocType = 'org.iso.18013.5.1.mDL';

/**
 * The document interface.
 */
export interface Doc {
  docType: DocType;
  issuerSigned?: IssuerSigned;
  deviceSigned?: DeviceSigned;
}

/**
 * Create the structure for encoding a document.
 *
 * @returns {Map<string, any>} - The document as a map
 */
export const prepare = (doc: Doc): Map<string, any> => {
  const docMap = new Map<string, any>();
  docMap.set('docType', doc.docType);
  docMap.set('issuerSigned', {
    nameSpaces: new Map(Object.entries(doc.issuerSigned?.nameSpaces ?? {}).map(([nameSpace, items]) => {
      return [nameSpace, items.map((item) => item.dataItem)];
    })),
    issuerAuth: doc.issuerSigned?.issuerAuth.getContentForEncoding(),
  });
  if (typeof doc.deviceSigned !== 'undefined') {
    // TODO
    docMap.set('deviceSigned', doc.deviceSigned);
  }
  return docMap;
};

/**
 * Represents an Issuer Signed Document.
 */
export type IssuerSignedDoc = Doc & { issuerSigned: IssuerSigned };

/**
 * The Document class.
 * Use this class when building new documents.
 */
export class Document implements Doc {
  readonly docType: DocType;
  #issuerNameSpaces: IssuerNameSpaces = {};
  #deviceKeyInfo: any;
  #validityInfo: ValidityInfo = {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: addYears(new Date(), 1),
    expectedUpdate: null,
  };
  #issuerSigned?: IssuerSigned;
  #deviceSigned?: DeviceSigned;
  #digestAlgorithm: DigestAlgorithm = 'SHA-256';

  constructor(doc: Doc | DocType = 'org.iso.18013.5.1.mDL') {
    if (typeof doc === 'string') {
      this.docType = doc;
    } else {
      this.docType = doc.docType;
      this.#issuerSigned = doc.issuerSigned;
      this.#deviceSigned = doc.deviceSigned;
    }
  }

  get issuerSigned() {
    return this.#issuerSigned;
  }

  get deviceSigned() {
    return this.#deviceSigned;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private validateValues(values: Record<string, any>) {
    // TODO
    // validate required fields, no extra fields, data types, etc...
  }

  /**
   * Add a namespace to an unsigned document.
   *
   * @param {string} namespace - The namespace to add.
   * @param {Record<string, any>} values - The values to add to the namespace.
   * @returns {Document} - The document
   */
  addIssuerNameSpace(namespace: 'org.iso.18013.5.1' | string, values: Record<string, any>): Document {
    if (this.issuerSigned) {
      throw new Error('Cannot add a namespace to an already signed document');
    }

    if (namespace === DEFAULT_NS) {
      this.validateValues(values);
    }

    this.#issuerNameSpaces[namespace] = this.#issuerNameSpaces[namespace] ?? [];

    const addAttribute = (key: string, value: any) => {
      const digestID = this.#issuerNameSpaces[namespace].length;
      const issuerSignedItem = IssuerSignedItem.create(digestID, key, value);
      this.#issuerNameSpaces[namespace].push(issuerSignedItem);
    };

    for (const [key, value] of Object.entries(values)) {
      addAttribute(key, value);
      if (key === 'birth_date') {
        const ageInYears = getAgeInYears(value);
        addAttribute('age_over_21', ageInYears >= 21);
        addAttribute(`age_over_${Math.floor(ageInYears)}`, Math.floor(ageInYears));
      }
    }

    return this;
  }

  /**
   * Add the device public key which will be include in the issuer signature.
   * The device public key could be in JWK format or as COSE_Key format.
   *
   * @param params
   * @param {jose.JWK | Uint8Array} params.devicePublicKey - The device public key.
   */
  addDeviceKeyInfo({ devicePublicKey }: { devicePublicKey: jose.JWK | Uint8Array }): Document {
    if (this.issuerSigned) {
      throw new Error('Cannot add the device public key to an already signed document');
    }

    const deviceKey =
      devicePublicKey instanceof Uint8Array ?
        devicePublicKey :
        COSEKeyFromJWK(devicePublicKey);

    this.#deviceKeyInfo = {
      deviceKey,
    };

    return this;
  }

  /**
   * Add validity info to the document that will be used in the issuer signature.
   *
   * @param info - the validity info
   * @param {Date} [info.signed] - The date the document is signed. default: now
   * @param {Date} [info.validFrom] - The date the document is valid from. default: signed
   * @param {Date} [info.validUntil] - The date the document is valid until. default: signed + 1 year
   * @param {Date} [info.expectedUpdate] - The date the document is expected to be updated. default: null
   * @returns
   */
  addValidityInfo(info: Partial<ValidityInfo> = {}): Document {
    if (this.issuerSigned) {
      throw new Error('Cannot add validity info to an already signed document');
    }
    const signed = info.signed ?? new Date();
    const validFrom = info.validFrom ?? signed;
    const validUntil = info.validUntil ?? addYears(signed, 1);
    this.#validityInfo = {
      signed,
      validFrom,
      validUntil,
      expectedUpdate: info.expectedUpdate,
    };
    return this;
  }

  /**
   * Set the digest algorithm used for the value digests in the issuer signature.
   *
   * The default is SHA-256.
   *
   * @param {DigestAlgorithm} digestAlgorithm - The digest algorithm to use.
   * @returns
   */
  useDigestAlgorithm(digestAlgorithm: DigestAlgorithm): Document {
    if (this.issuerSigned) {
      throw new Error('Cannot change digest algorithm of an already signed document');
    }
    this.#digestAlgorithm = digestAlgorithm;
    return this;
  }

  /**
   * Generate the issuer signature for the document.
   *
   * @param params.issuerPrivateKey - The issuer's private key
   * @param params.issuerCertificate - The issuer's certificate in pem format.
   * @param params.devicePublicKey - The device's public key
   * @returns {Promise<IssuerSignedDoc>} - The signed document
   */
  async sign(params: {
    issuerPrivateKey: jose.KeyLike,
    issuerCertificate: string,
  }): Promise<Document & IssuerSignedDoc> {
    if (this.issuerSigned) {
      throw new Error('Cannot add namespace to an already signed document');
    }
    if (!this.#issuerNameSpaces) {
      throw new Error('No namespaces added');
    }

    const issuerPublicKeyBuffer = fromPEM(params.issuerCertificate);

    const valueDigests = new Map(await Promise.all(Object.entries(this.#issuerNameSpaces).map(async ([namespace, items]) => {
      const digestMap = new Map<number, Uint8Array>();
      await Promise.all(items.map(async (item, index) => {
        const hash = await item.calculateDigest(this.#digestAlgorithm);
        digestMap.set(index, new Uint8Array(hash));
      }));
      return [namespace, digestMap] as [string, Map<number, Uint8Array>];
    })));

    const mso: MSO = {
      version: '1.0',
      digestAlgorithm: this.#digestAlgorithm,
      valueDigests,
      deviceKeyInfo: this.#deviceKeyInfo,
      docType: this.docType,
      validityInfo: this.#validityInfo,
    };

    const payload = cborEncode(DataItem.fromData(mso));
    const protectedHeader: ProtectedHeader = { alg: 'ES256' };
    const unprotectedHeader: UnprotectedHeaders = { kid: '11', x5chain: [issuerPublicKeyBuffer] };
    const issuerAuth = await IssuerAuth.sign(protectedHeader, unprotectedHeader, payload, params.issuerPrivateKey) as IssuerAuth;

    this.#issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    };

    return this;
  }
}
