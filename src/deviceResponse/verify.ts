import { Tagged } from 'cbor';
import { compareVersions } from 'compare-versions';
import CoseSign1 from '../cose/CoseSign1';
import CoseMac0 from '../cose/CoseMac0';
import { cborDecode } from '../cose/cbor';
import { extractX5Chain } from '../cose/headers';
import coseKeyMapToBuffer from '../cose/coseKey';
import {
  calculateDigest,
  calculateEphemeralMacKey,
  calculateDeviceAutenticationBytes,
  parseAndValidateCertificateChain,
} from './utils';
import {
  RawMobileDocument,
  RawIssuerAuth,
  RawDeviceAuth,
  RawIssuerNameSpaces,
  IssuerNameSpaces,
  IssuerSignedItem,
  IssuerAuth,
  DeviceAuth,
  DeviceNameSpaces,
  DeviceSignedItems,
  RawDeviceNameSpaces,
  ParsedDeviceResponse,
  DSCertificate,
  MobileDocument,
  ValidatedIssuerNameSpaces,
  ValidityInfo,
  VerificationSummary,
} from './types.d';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as { [key: string]: string };

export default class DeviceResponseVerifier {
  private readonly issuersRootCertificates: string[];

  private summary: VerificationSummary;

  /**
   *
   * @param issuersRootCertificates The IACA root certificates list of the supported issuers.
   */
  constructor(issuersRootCertificates: string[]) {
    this.issuersRootCertificates = issuersRootCertificates;
    this.summary = [];
  }

  /* Getters and setters */
  getIssuersRootCertificates(): string[] {
    return this.issuersRootCertificates;
  }

  getVerificationSummary(): VerificationSummary {
    return this.summary;
  }

  getVerificationErrors(): VerificationSummary {
    return this.summary.filter((el) => el.level === 'error');
  }

  getIsValid(): boolean {
    return this.summary.length > 0 && this.getVerificationErrors().length === 0;
  }

  private parseIssuerAuthElement(
    rawIssuerAuth: RawIssuerAuth,
    expectedDocType: string,
  ): IssuerAuth {
    const issuerAuth = new CoseSign1(rawIssuerAuth);
    const { docType, version } = issuerAuth.getDecodedPayload();

    if (docType !== expectedDocType) {
      this.summary.push({ level: 'error', msg: `The issuerAuth docType must be ${expectedDocType}` });
    } else {
      this.summary.push({ level: 'info', msg: `The issuerAuth docType is valid: ${docType}` });
    }

    if (!version || compareVersions(version, '1.0') !== 0) {
      this.summary.push({ level: 'error', msg: 'The issuerAuth  version must be \'1.0\'' });
    } else {
      this.summary.push({ level: 'info', msg: `The issuerAuth version is valid: ${version}` });
    }

    return issuerAuth;
  }

  private parseDeviceAuthElement(rawDeviceAuth: RawDeviceAuth): DeviceAuth {
    if (rawDeviceAuth.deviceSignature) {
      this.summary.push({ level: 'info', msg: 'Using ECDSA/EdDSA for device authentication' });
      return { deviceSignature: new CoseSign1(rawDeviceAuth.deviceSignature) };
    }

    this.summary.push({ level: 'info', msg: 'Using MAC for device authentication' });
    return { deviceMac: new CoseMac0(rawDeviceAuth.deviceMac) };
  }

  private parseIssuerNameSpaces(rawIssuerNameSpaces: RawIssuerNameSpaces): IssuerNameSpaces {
    const nameSpaces: IssuerNameSpaces = {};

    Object.keys(rawIssuerNameSpaces).forEach((ns) => {
      nameSpaces[ns] = rawIssuerNameSpaces[ns].map(
        (t) => cborDecode(t.value) as IssuerSignedItem,
      );
    });

    this.summary.push({ level: 'info', msg: 'Issuer namespaces were decoded' });
    return nameSpaces;
  }

  private parseDeviceNameSpaces(rawDeviceNameSpaces: RawDeviceNameSpaces): DeviceNameSpaces {
    const nameSpaces: DeviceNameSpaces = {};

    if (rawDeviceNameSpaces instanceof Tagged) {
      this.summary.push({ level: 'info', msg: 'Device namespaces are empty' });
      return cborDecode(rawDeviceNameSpaces.value) as DeviceNameSpaces;
    }

    Object.keys(rawDeviceNameSpaces).forEach((ns) => {
      nameSpaces[ns] = cborDecode(rawDeviceNameSpaces[ns].value) as DeviceSignedItems;
    });

    this.summary.push({ level: 'info', msg: 'Device namespaces were decoded' });
    return nameSpaces;
  }

  private async verifyIssuerSignature(msg: IssuerAuth):
    Promise<{ validityInfo: ValidityInfo, dsCertificate: DSCertificate } | { validityInfo: undefined, dsCertificate: undefined }> {
    // Confirm that the mdoc data is issued by the issuing authority

    try {
      // Parse and validate issuer certificate
      const rawIssuerCertChain = extractX5Chain(msg);
      const issuerCert = await parseAndValidateCertificateChain(rawIssuerCertChain, this.issuersRootCertificates);

      this.summary.push({ level: 'info', msg: 'The certificate chain (x5c) is valid' });

      // Verify signature
      const verificationResult = await msg.verify(issuerCert.publicKey.rawData);
      if (!verificationResult) {
        throw new Error('The signature is tempered');
      } else {
        this.summary.push({ level: 'info', msg: 'The issuerAuth signature is valid' });
      }

      // Validity
      const { validityInfo } = msg.getDecodedPayload();
      const now = new Date();
      if (validityInfo.signed < issuerCert.notBefore && validityInfo.signed > issuerCert.notAfter) {
        this.summary.push({ level: 'error', msg: `The MSO signed date (${validityInfo.signed.toUTCString()}) is not within the validity period of the certificate (${issuerCert.notBefore.toUTCString()} to ${issuerCert.notAfter.toUTCString()})` });
      } else {
        this.summary.push({ level: 'info', msg: `The MSO signed date (${validityInfo.signed.toUTCString()}) is within the validity period of the certificate (${issuerCert.notBefore.toUTCString()} to ${issuerCert.notAfter.toUTCString()})` });
      }

      if (now < validityInfo.validFrom) {
        this.summary.push({ level: 'error', msg: `The MSO is not valid until ${validityInfo.validFrom.toUTCString()}` });
      } else {
        this.summary.push({ level: 'info', msg: `The MSO is valid from ${validityInfo.validFrom.toUTCString()}` });
      }

      if (validityInfo.validUntil < now) {
        this.summary.push({ level: 'error', msg: `The MSO was expired at ${validityInfo.validUntil.toUTCString()}` });
      } else {
        this.summary.push({ level: 'info', msg: `The MSO is valid until ${validityInfo.validUntil.toUTCString()}` });
      }

      // countryName is mandatory, stateOrProvinceName is optional
      const stateOrProvinceName = issuerCert.issuerName.getField('ST')[0];
      const countryName = issuerCert.issuerName.getField('C')[0];
      if (!countryName) {
        this.summary.push({ level: 'error', msg: 'Country name (C) not found in the issuer certificate\'s subject distinguished name' });
      } else {
        this.summary.push({ level: 'info', msg: `The countryName and stateOrProvinceName taken from issuer certificate subject distinguished name are ${countryName} and ${stateOrProvinceName} respectively` });
      }

      return {
        validityInfo,
        dsCertificate: {
          issuer: { countryName, stateOrProvinceName },
          validity: { notBefore: issuerCert.notBefore, notAfter: issuerCert.notAfter },
        },
      };
    } catch (err) {
      this.summary.push({ level: 'error', msg: `Unable to verify issuer signature: ${err.message}` });
      return { validityInfo: undefined, dsCertificate: undefined };
    }
  }

  private async verifyDeviceSignature(
    deviceAuth: DeviceAuth,
    options: {
      deviceKeyCoseKey: Map<number, Buffer | number>;
      ephemeralPrivateKey: Buffer;
      sessionTranscriptBytes: Buffer;
      docType: string;
      nameSpaces: RawDeviceNameSpaces;
    },
  ) {
    // Prevent cloning of the mdoc and mitigate man in the middle attacks
    if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
      this.summary.push({ level: 'error', msg: 'The deviceAuth does not contain a deviceSignature or deviceMac element' });
      return;
    }

    const deviceKey = coseKeyMapToBuffer(options.deviceKeyCoseKey);
    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      options.sessionTranscriptBytes,
      options.docType,
      options.nameSpaces,
    );

    if (deviceAuth.deviceSignature) {
      // ECDSA/EdDSA authentication
      try {
        const verificationResult = await deviceAuth.deviceSignature.verify(deviceKey, deviceAuthenticationBytes);
        if (!verificationResult) {
          this.summary.push({ level: 'error', msg: 'The deviceAuth signature (ECDSA/EdDSA) is tempered' });
        } else {
          this.summary.push({ level: 'info', msg: 'The deviceAuth signature (ECDSA/EdDSA) is valid' });
        }
      } catch (err) {
        this.summary.push({ level: 'error', msg: `Unable to validate deviceAuth signature (ECDSA/EdDSA): ${err.message}` });
      }

      return;
    }

    // MAC authentication
    if (!options.ephemeralPrivateKey) {
      this.summary.push({ level: 'error', msg: 'Unable to calculate device MAC because ephemeralPrivateKey was not specified' });
      return;
    }

    if (!deviceAuth.deviceMac.hasSupportedAlg()) {
      this.summary.push({ level: 'error', msg: 'Unsupported deviceMac alg, expected: 5 (HMAC 256/256)' });
      return;
    }

    try {
      const ephemeralMacKey = calculateEphemeralMacKey(
        deviceKey,
        options.ephemeralPrivateKey,
        options.sessionTranscriptBytes,
      );

      const expectedMac = await CoseMac0.generate(
        ephemeralMacKey,
        Buffer.alloc(0),
        deviceAuthenticationBytes,
      );

      if (expectedMac.getTag().compare(deviceAuth.deviceMac.getTag()) !== 0) {
        this.summary.push({ level: 'error', msg: 'Device MAC mismatch' });
      } else {
        this.summary.push({ level: 'info', msg: 'The deviceAuth signature (MAC) is valid' });
      }
    } catch (err) {
      this.summary.push({ level: 'error', msg: 'Unexpected error during device MAC computation' });
    }
  }

  private verifyData(mdoc: MobileDocument, dsCertificate: DSCertificate): {
    issuerNameSpaces: ValidatedIssuerNameSpaces, deviceNameSpaces: DeviceNameSpaces
  } {
    // Confirm that the mdoc data has not changed since issuance
    const { issuerAuth } = mdoc.issuerSigned;
    const { valueDigests, digestAlgorithm } = cborDecode(
      issuerAuth.getPayload(),
    ) as { valueDigests: { [x: string]: Map<number, Buffer> }, digestAlgorithm: string };

    if (!digestAlgorithm || !DIGEST_ALGS[digestAlgorithm]) {
      this.summary.push({ level: 'error', msg: `Unsupported digests algorithm: ${digestAlgorithm}` });
    }

    const nameSpaces = mdoc.issuerSigned.nameSpaces || {};
    const issuerNameSpaces = {} as ValidatedIssuerNameSpaces;

    Object.keys(nameSpaces).forEach((ns) => {
      const digests = valueDigests[ns];
      if (!digests) {
        this.summary.push({ level: 'error', msg: `Unable to find digests for namespace: ${ns}` });
        return;
      }

      issuerNameSpaces[ns] = {};

      nameSpaces[ns].forEach((ev, i) => {
        const digest = digests.get(ev.digestID);
        const expectedDigest = calculateDigest(DIGEST_ALGS[digestAlgorithm], mdoc.raw.issuerSigned.nameSpaces[ns][i]);
        if (digest.compare(expectedDigest) !== 0) {
          this.summary.push({ level: 'error', msg: `Invalid digest for ${ns}/${ev.elementIdentifier} element` });
        } else {
          this.summary.push({ level: 'info', msg: `Valid digest for ${ns}/${ev.elementIdentifier} element` });
          issuerNameSpaces[ns][ev.elementIdentifier] = ev.elementValue;
        }
      });

      if (ns === MDL_NAMESPACE) {
        // if the `issuing_country` was retrieved, verify that the value matches the `countryName` in the subject field within the DS certificate
        if (issuerNameSpaces[ns].issuing_country
          && issuerNameSpaces[ns].issuing_country !== dsCertificate.issuer.countryName) {
          this.summary.push({ level: 'error', msg: `The 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) must match the 'countryName' (${dsCertificate.issuer.countryName}) in the subject field within the DS certificate` });
        } else if (issuerNameSpaces[ns].issuing_country) {
          this.summary.push({ level: 'info', msg: `The retrieved 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) matches the 'countryName' (${dsCertificate.issuer.countryName}) in the subject field within the DS certificate` });
        } else {
          this.summary.push({ level: 'info', msg: 'The \'issuing_country\' was not retrieved' });
        }

        // if the `issuing_jurisdiction` was retrieved, and `stateOrProvinceName` is present in the subject field within the DS certificate, they must have the same value
        if (issuerNameSpaces[ns].issuing_jurisdiction
          && dsCertificate.issuer.stateOrProvinceName
          && issuerNameSpaces[ns].issuing_jurisdiction !== dsCertificate.issuer.stateOrProvinceName) {
          this.summary.push({ level: 'error', msg: `The 'issuing_jurisdiction' (${issuerNameSpaces[ns].issuing_jurisdiction}) must match the 'stateOrProvinceName' (${dsCertificate.issuer.stateOrProvinceName}) in the subject field within the DS certificate` });
        } else if (issuerNameSpaces[ns].issuing_jurisdiction && !dsCertificate.issuer.stateOrProvinceName) {
          this.summary.push({ level: 'warn', msg: `The 'issuing_jurisdiction' was retrieved (${issuerNameSpaces[ns].issuing_jurisdiction}) but the 'stateOrProvinceName' is not present in the subject field within the DS certificate` });
        } else if (!issuerNameSpaces[ns].issuing_jurisdiction) {
          this.summary.push({ level: 'info', msg: 'The \'issuing_jurisdiction\' was not retrieved' });
        } else {
          this.summary.push({ level: 'info', msg: `The 'issuing_jurisdiction' (${issuerNameSpaces[ns].issuing_jurisdiction}) matches the 'stateOrProvinceName' (${dsCertificate.issuer.stateOrProvinceName}) in the subject field within the DS certificate` });
        }
      }
    });

    return { issuerNameSpaces, deviceNameSpaces: mdoc.deviceSigned.nameSpaces };
  }

  /**
   * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
   *
   * @param encodedDeviceResponse
   * @param options.encodedSessionTranscript The CBOR encoded SessionTranscript.
   * @param options.ephemeralReaderKey The private part of the ephemeral key used in the session where the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC method for device authentication.
   */
  async verify(
    encodedDeviceResponse: Buffer,
    options: { encodedSessionTranscript: Buffer, ephemeralReaderKey?: Buffer },
  ): Promise<ParsedDeviceResponse> {
    this.summary = [];
    let deviceResponse;

    try {
      deviceResponse = cborDecode(encodedDeviceResponse, { skipExtraTags: true }) as {
        version: string,
        documents: Array<unknown>
      };
    } catch (err) {
      this.summary.push({ level: 'error', msg: `Unable to decode device response: ${err.message}` });
      return { isValid: false };
    }

    if (!deviceResponse.version) {
      this.summary.push({ level: 'error', msg: 'Device response doesn\'t contain the \'version\' element' });
    }

    if (compareVersions(deviceResponse.version, '1.0') < 0) {
      this.summary.push({ level: 'error', msg: `Device response has an unsupported version: ${deviceResponse.version} (expected: >= '1.0')` });
    } else {
      this.summary.push({ level: 'info', msg: `Device response version is valid: ${deviceResponse.version}` });
    }

    if (!deviceResponse.documents || deviceResponse.documents.length === 0) {
      this.summary.push({ level: 'error', msg: 'Device response is invalid since it doesn\'t contain \'documents\' elements' });
    } else {
      this.summary.push({ level: 'info', msg: 'Device response contains at least one \'document\' element' });
    }

    const mdoc = deviceResponse.documents.map((doc: RawMobileDocument) => ({
      docType: doc.docType,
      raw: doc,
      issuerSigned: {
        issuerAuth: this.parseIssuerAuthElement(doc.issuerSigned.issuerAuth, doc.docType),
        nameSpaces: this.parseIssuerNameSpaces(doc.issuerSigned.nameSpaces),
      },
      deviceSigned: {
        deviceAuth: this.parseDeviceAuthElement(doc.deviceSigned.deviceAuth),
        nameSpaces: this.parseDeviceNameSpaces(doc.deviceSigned.nameSpaces),
      },
    }));

    // TODO: support multiple docs
    const { issuerAuth } = mdoc[0].issuerSigned;
    const { deviceKey } = issuerAuth.getDecodedPayload().deviceKeyInfo;
    const { validityInfo, dsCertificate } = await this.verifyIssuerSignature(issuerAuth);

    await this.verifyDeviceSignature(mdoc[0].deviceSigned.deviceAuth as DeviceAuth, {
      deviceKeyCoseKey: deviceKey as Map<number, Buffer | number>,
      ephemeralPrivateKey: options.ephemeralReaderKey,
      sessionTranscriptBytes: options.encodedSessionTranscript,
      docType: mdoc[0].docType,
      nameSpaces: mdoc[0].raw.deviceSigned.nameSpaces,
    });

    const data = dsCertificate && this.verifyData(mdoc[0], dsCertificate);

    return {
      isValid: this.getIsValid(),
      issuer: { nameSpaces: data?.issuerNameSpaces, validityInfo, dsCertificate },
      device: { nameSpaces: data?.deviceNameSpaces },
    };
  }
}
