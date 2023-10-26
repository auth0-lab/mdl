import * as jose from 'jose';
import { COSEKeyFromJWK, COSEKeyToJWK, ProtectedHeaders, UnprotectedHeaders } from 'cose-kit';
import { fromPEM } from '../utils';
import { DataItem, cborEncode } from '../../cbor';
import { IssuerSignedItem } from '../IssuerSignedItem';
import IssuerAuth from './IssuerAuth';
import { DigestAlgorithm, DocType, IssuerNameSpaces, MSO, MSOSupportedAlgs, ValidityInfo } from './types';
import { IssuerSignedDocument } from './IssuerSignedDocument';

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

/**
 * Use this class when building new documents.
 *
 * This class allow you to build a document and sign it with the issuer's private key.
 */
export class Document {
  readonly docType: DocType;
  #issuerNameSpaces: IssuerNameSpaces = {};
  #deviceKeyInfo: any;
  #validityInfo: ValidityInfo = {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: addYears(new Date(), 1),
    expectedUpdate: null,
  };
  #digestAlgorithm: DigestAlgorithm = 'SHA-256';

  constructor(doc: DocType = 'org.iso.18013.5.1.mDL') {
    this.docType = doc;
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
        addAttribute(`age_over_${Math.floor(ageInYears)}`, true);
      }
    }

    return this;
  }

  /**
   * Get the values in a namespace.
   *
   * @param {string} namespace - The namespace to add.
   * @returns {Record<string, any>} - The values in the namespace as an object
   */
  getIssuerNameSpace(namespace: string): Record<string, any> {
    const nameSpace = this.#issuerNameSpaces[namespace];
    return Object.fromEntries(
      nameSpace.map((item) => [item.elementIdentifier, item.elementValue]),
    );
  }

  /**
   * Add the device public key which will be include in the issuer signature.
   * The device public key could be in JWK format or as COSE_Key format.
   *
   * @param params
   * @param {jose.JWK | Uint8Array} params.devicePublicKey - The device public key.
   */
  addDeviceKeyInfo({ devicePublicKey }: { devicePublicKey: jose.JWK | Uint8Array }): Document {
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
    this.#digestAlgorithm = digestAlgorithm;
    return this;
  }

  /**
   * Generate the issuer signature for the document.
   *
   * @param {Object} params - The parameters object
   * @param {jose.JWK | Uint8Array} params.issuerPrivateKey - The issuer's private key either in JWK format or COSE_KEY format as buffer.
   * @param {string | Uint8Array} params.issuerCertificate - The issuer's certificate in pem format or as a buffer.
   * @param {MSOSupportedAlgs} params.alg - The algorhitm used for the MSO signature.
   * @param {string | Uint8Array} [params.kid] - The key id of the issuer's private key. default: issuerPrivateKey.kid
   * @returns {Promise<IssuerSignedDoc>} - The signed document
   */
  async sign(params: {
    issuerPrivateKey: jose.JWK | Uint8Array,
    issuerCertificate: string | Uint8Array,
    alg: MSOSupportedAlgs,
    kid?: string | Uint8Array,
  }): Promise<IssuerSignedDocument> {
    if (!this.#issuerNameSpaces) {
      throw new Error('No namespaces added');
    }

    const issuerPublicKeyBuffer = typeof params.issuerCertificate === 'string' ?
      fromPEM(params.issuerCertificate) :
      params.issuerCertificate;

    const issuerPrivateKeyJWK = params.issuerPrivateKey instanceof Uint8Array ?
      COSEKeyToJWK(params.issuerPrivateKey) :
      params.issuerPrivateKey;

    const issuerPrivateKey = await jose.importJWK(issuerPrivateKeyJWK);

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
    const protectedHeader: ProtectedHeaders = { alg: params.alg };
    const unprotectedHeader: UnprotectedHeaders = {
      kid: params.kid ?? issuerPrivateKeyJWK.kid,
      x5chain: [issuerPublicKeyBuffer],
    };

    const issuerAuth = await IssuerAuth.sign(
      protectedHeader,
      unprotectedHeader,
      payload,
      issuerPrivateKey,
    );

    const issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    };

    return new IssuerSignedDocument(this.docType, issuerSigned);
  }
}
