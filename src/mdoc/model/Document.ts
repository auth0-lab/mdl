import * as jose from 'jose';
import { COSEKeyFromJWK, COSEKeyToJWK, ProtectedHeaders, UnprotectedHeaders } from 'cose-kit';
import { fromPEM } from '../utils';
import { DataItem, DateOnly, cborDecode, cborEncode } from '../../cbor';
import { IssuerSignedItem } from '../IssuerSignedItem';
import IssuerAuth from './IssuerAuth';
import { DeviceKeyInfo, DigestAlgorithm, DocType, IssuerNameSpaces, MSO, SupportedAlgs, ValidityInfo } from './types';
import { IssuerSignedDocument } from './IssuerSignedDocument';
import { Signer } from '../signing/Signer';

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
        COSEKeyFromJWK(deviceKey);
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
   * @param {jose.JWK | Uint8Array} [params.issuerPrivateKey] - The issuer's private key either in JWK format or COSE_KEY format as buffer. Required if signer is not provided.
   * @param {Signer} [params.signer] - A Signer implementation for custom signing (e.g., AzureKeyVaultSigner). Required if issuerPrivateKey is not provided.
   * @param {string | Uint8Array | Array<string | Uint8Array>} params.issuerCertificate - The issuer's certificate in pem format, as a buffer, or an array.
   * @param {SupportedAlgs} params.alg - The algorhitm used for the MSO signature.
   * @param {string | Uint8Array} [params.kid] - The key id of the issuer's private key. default: issuerPrivateKey.kid or signer.getKeyId()
   * @returns {Promise<IssuerSignedDoc>} - The signed document
   */
  async sign(params: {
    issuerPrivateKey?: jose.JWK | Uint8Array,
    signer?: Signer,
    issuerCertificate: string | Uint8Array | Array<string | Uint8Array>,
    alg: SupportedAlgs,
    kid?: string | Uint8Array,
  }): Promise<IssuerSignedDocument> {
    if (!this.#issuerNameSpaces) {
      throw new Error('No namespaces added');
    }

    // Validate that either issuerPrivateKey or signer is provided (but not both)
    if (!params.issuerPrivateKey && !params.signer) {
      throw new Error('Must provide either issuerPrivateKey or signer');
    }
    if (params.issuerPrivateKey && params.signer) {
      throw new Error('Cannot provide both issuerPrivateKey and signer. Use one or the other.');
    }

    let issuerCertificateChain: Uint8Array[];

    if (Array.isArray(params.issuerCertificate)) {
      issuerCertificateChain = params.issuerCertificate.flatMap((cert) => (typeof cert === 'string' ? fromPEM(cert) : [cert]));
    } else if (typeof params.issuerCertificate === 'string') {
      issuerCertificateChain = fromPEM(params.issuerCertificate);
    } else {
      issuerCertificateChain = [params.issuerCertificate];
    }

    // Prepare key material based on what was provided
    let issuerPrivateKeyJWK: jose.JWK | undefined;
    let issuerPrivateKey: jose.KeyLike | Uint8Array | undefined;

    if (params.issuerPrivateKey) {
      issuerPrivateKeyJWK = params.issuerPrivateKey instanceof Uint8Array ?
        COSEKeyToJWK(params.issuerPrivateKey) :
        params.issuerPrivateKey;
      issuerPrivateKey = await jose.importJWK(issuerPrivateKeyJWK);
    }

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

    const payload = new Uint8Array(cborEncode(DataItem.fromData(mso)));
    const protectedHeader: ProtectedHeaders = { alg: params.alg };

    // Determine kid from params, issuerPrivateKeyJWK, or signer
    const { kid: paramKid, signer } = params;
    let kid: string | Uint8Array | undefined = paramKid;
    if (!kid && issuerPrivateKeyJWK) {
      kid = issuerPrivateKeyJWK.kid;
    } else if (!kid && signer) {
      kid = signer.getKeyId();
    }

    const unprotectedHeader: UnprotectedHeaders = {
      kid,
      x5chain: issuerCertificateChain.length === 1 ? issuerCertificateChain[0] : issuerCertificateChain,
    };

    // Use either traditional signing or custom signer
    const issuerAuth = signer ?
      await IssuerAuth.signWithSigner(
        protectedHeader,
        unprotectedHeader,
        payload,
        signer,
        params.alg,
      ) :
      await IssuerAuth.sign(
        protectedHeader,
        unprotectedHeader,
        payload,
        issuerPrivateKey!,
      );

    const issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    };

    return new IssuerSignedDocument(this.docType, issuerSigned);
  }
}
