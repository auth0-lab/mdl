import * as jose from 'jose';
import { COSEKey, ProtectedHeaders, UnprotectedHeaders, Headers, Algorithms } from 'cose-kit';
import { fromPEM } from '../utils';
import { DataItem, DateOnly, cborDecode, cborEncode } from '../../cbor';
import { IssuerSignedItem } from '../IssuerSignedItem';
import IssuerAuth from './IssuerAuth';
import { DeviceKeyInfo, DigestAlgorithm, DocType, IssuerNameSpaces, MSO, SupportedAlgs, ValidityInfo } from './types';
import { IssuerSignedDocument } from './IssuerSignedDocument';

const DEFAULT_NS = 'org.iso.18013.5.1';

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
  #deviceKeyInfo: DeviceKeyInfo;
  #validityInfo: ValidityInfo = {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: addYears(new Date(), 1),
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
      let elementValue = value;

      if (namespace === DEFAULT_NS) {
        // the following namespace attributes must be a full-date as specified in RFC 3339
        if (['birth_date', 'issue_date', 'expiry_date'].includes(key) && typeof value === 'string') {
          elementValue = new DateOnly(value);
        }

        if (key === 'driving_privileges' && Array.isArray(value)) {
          value.forEach((v, i) => {
            if (typeof v.issue_date === 'string') { elementValue[i].issue_date = new DateOnly(v.issue_date); }
            if (typeof v.expiry_date === 'string') { elementValue[i].expiry_date = new DateOnly(v.expiry_date); }
          });
        }
      }

      const digestID = this.#issuerNameSpaces[namespace].length;
      const issuerSignedItem = IssuerSignedItem.create(digestID, key, elementValue);
      this.#issuerNameSpaces[namespace].push(issuerSignedItem);
    };

    for (const [key, value] of Object.entries(values)) {
      addAttribute(key, value);
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
  addDeviceKeyInfo({ deviceKey }: { deviceKey: jose.JWK | Uint8Array }): Document {
    const deviceKeyCOSEKey =
      deviceKey instanceof Uint8Array ?
        deviceKey :
        COSEKey.fromJWK(deviceKey).encode();
    const decodedCoseKey = cborDecode(deviceKeyCOSEKey);

    this.#deviceKeyInfo = {
      deviceKey: decodedCoseKey,
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
   * @param {Date} [info.expectedUpdate] - [Optional] The date the document is expected to be re-signed and potentially have its data updated.
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
    };

    if (info.expectedUpdate) {
      this.#validityInfo.expectedUpdate = info.expectedUpdate;
    }

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
   * @param {string | Uint8Array | Array<string | Uint8Array>} params.issuerCertificate - The issuer's certificate in pem format, as a buffer, or an array.
   * @param {SupportedAlgs} params.alg - The algorhitm used for the MSO signature.
   * @param {string | Uint8Array} [params.kid] - The key id of the issuer's private key. default: issuerPrivateKey.kid
   * @returns {Promise<IssuerSignedDoc>} - The signed document
   */
  async sign(params: {
    issuerPrivateKey: jose.JWK | Uint8Array,
    issuerCertificate: string | Uint8Array | Array<string | Uint8Array>,
    alg: SupportedAlgs,
    kid?: string | Uint8Array,
  }): Promise<IssuerSignedDocument> {
    if (!this.#issuerNameSpaces) {
      throw new Error('No namespaces added');
    }

    let issuerCertificateChain: Uint8Array[];

    if (Array.isArray(params.issuerCertificate)) {
      issuerCertificateChain = params.issuerCertificate.flatMap((cert) => (typeof cert === 'string' ? fromPEM(cert) : [cert]));
    } else if (typeof params.issuerCertificate === 'string') {
      issuerCertificateChain = fromPEM(params.issuerCertificate);
    } else {
      issuerCertificateChain = [params.issuerCertificate];
    }

    const issuerPrivateKeyJWK = params.issuerPrivateKey instanceof Uint8Array ?
      COSEKey.import(params.issuerPrivateKey).toJWK() :
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
    const protectedHeader: ProtectedHeaders = new ProtectedHeaders();
    protectedHeader.set(Headers.Algorithm, Algorithms[params.alg]);

    const unprotectedHeader: UnprotectedHeaders = new UnprotectedHeaders()
    if (params.kid) {
      unprotectedHeader.set(Headers.KeyID, typeof params.kid === 'string' ? new TextEncoder().encode(params.kid) : params.kid);
    }
    unprotectedHeader.set(Headers.X5Chain, issuerCertificateChain.length === 1 ? issuerCertificateChain[0] : issuerCertificateChain);

    const issuerAuth = await IssuerAuth.sign(
      protectedHeader,
      unprotectedHeader,
      Uint8Array.from(payload),
      issuerPrivateKey,
    );

    const issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    };

    return new IssuerSignedDocument(this.docType, issuerSigned);
  }
}
