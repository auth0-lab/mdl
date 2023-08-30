import { compareVersions } from 'compare-versions';
import CoseSign1 from '../cose/CoseSign1';
import CoseMac0 from '../cose/CoseMac0';
import { extractX5Chain } from '../cose/headers';
import coseKeyMapToBuffer from '../cose/coseKey';
import {
  calculateEphemeralMacKey,
  calculateDeviceAutenticationBytes,
  parseAndValidateCertificateChain,
} from './utils';
import {
  RawIssuerAuth,
  IssuerAuth,
  DeviceAuth,
  ParsedDeviceResponse,
  DSCertificate,
  MobileDocument,
  ValidatedIssuerNameSpaces,
  ValidityInfo,
  VerificationSummary,
  NameSpaces,
  DeviceResponse,
} from './types';
import { parse } from './parser';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as { [key: string]: string };

export class DeviceResponseVerifier {
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
    const { docType, version } = issuerAuth.decodedPayload;

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

  private async verifyIssuerSignature(msg: IssuerAuth):
    Promise<{ validityInfo: ValidityInfo, dsCertificate: DSCertificate } | { validityInfo: undefined, dsCertificate: undefined }> {
    // Confirm that the mdoc data is issued by the issuing authority

    try {
      // Parse and validate issuer certificate
      const rawIssuerCertChain = extractX5Chain(msg);
      const issuerCert = await parseAndValidateCertificateChain(rawIssuerCertChain, this.issuersRootCertificates);

      this.summary.push({ level: 'info', msg: 'The certificate chain (x5c) is valid' });

      // Verify signature
      const verificationResult = await msg.verify(issuerCert.publicKey.rawData, { publicKeyFormat: 'spki' });
      if (!verificationResult) {
        throw new Error('The signature is tempered');
      } else {
        this.summary.push({ level: 'info', msg: 'The issuerAuth signature is valid' });
      }

      // Validity
      const { validityInfo } = msg.decodedPayload;
      const now = new Date();
      if (validityInfo.signed < issuerCert.notBefore || validityInfo.signed > issuerCert.notAfter) {
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
      nameSpaces: NameSpaces;
    },
  ) {
    // Prevent cloning of the mdoc and mitigate man in the middle attacks
    if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
      this.summary.push({ level: 'error', msg: 'The deviceAuth does not contain a deviceSignature or deviceMac element' });
      return;
    }

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      options.sessionTranscriptBytes,
      options.docType,
      options.nameSpaces,
    );

    if (deviceAuth.deviceSignature) {
      // ECDSA/EdDSA authentication
      try {
        const deviceKey = coseKeyMapToBuffer(options.deviceKeyCoseKey);
        const verificationResult = await deviceAuth.deviceSignature.verify(deviceKey, { publicKeyFormat: 'raw', detachedContent: deviceAuthenticationBytes });
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
      const deviceKey = coseKeyMapToBuffer(options.deviceKeyCoseKey);
      const ephemeralMacKey = await calculateEphemeralMacKey(
        deviceKey,
        options.ephemeralPrivateKey,
        options.sessionTranscriptBytes,
      );

      const expectedMac = await CoseMac0.generate(
        ephemeralMacKey,
        Buffer.alloc(0),
        deviceAuthenticationBytes,
      );

      if (expectedMac.tag.compare(deviceAuth.deviceMac.tag) !== 0) {
        this.summary.push({ level: 'error', msg: 'Device MAC mismatch' });
      } else {
        this.summary.push({ level: 'info', msg: 'The deviceAuth signature (MAC) is valid' });
      }
    } catch (err) {
      this.summary.push({ level: 'error', msg: `Unexpected error during device MAC computation: ${err.message}` });
    }
  }

  private async verifyData(mdoc: MobileDocument, dsCertificate: DSCertificate): Promise<{
    issuerNameSpaces: ValidatedIssuerNameSpaces, deviceNameSpaces: NameSpaces
  }> {
    // Confirm that the mdoc data has not changed since issuance
    const { issuerAuth } = mdoc.issuerSigned;
    const { valueDigests, digestAlgorithm } = issuerAuth.decodedPayload;

    if (!digestAlgorithm || !DIGEST_ALGS[digestAlgorithm]) {
      this.summary.push({ level: 'error', msg: `Unsupported digests algorithm: ${digestAlgorithm}` });
    }

    const nameSpaces = mdoc.issuerSigned.nameSpaces || {};
    const issuerNameSpaces: ValidatedIssuerNameSpaces = {};

    await Promise.all(Object.keys(nameSpaces).map(async (ns) => {
      const digests = valueDigests.get(ns);
      if (!digests) {
        this.summary.push({ level: 'error', msg: `Unable to find digests for namespace: ${ns}` });
        return;
      }

      issuerNameSpaces[ns] = {};

      await Promise.all(nameSpaces[ns].map(async (ev) => {
        const digest = digests.get(ev.digestID);
        const expectedDigest = await ev.calculateDigest(digestAlgorithm);
        if (digest.compare(new Uint8Array(expectedDigest)) !== 0) {
          this.summary.push({ level: 'error', msg: `Invalid digest for ${ns}/${ev.elementIdentifier} element` });
        } else {
          this.summary.push({ level: 'info', msg: `Valid digest for ${ns}/${ev.elementIdentifier} element` });
          issuerNameSpaces[ns][ev.elementIdentifier] = ev.elementValue;
        }
      }));

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
    }));

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
    let dr: DeviceResponse;

    try {
      dr = await parse(encodedDeviceResponse);
    } catch (err) {
      this.summary.push({ level: 'error', msg: `Unable to decode device response: ${err.message}` });
      return { isValid: false };
    }

    // TODO: support multiple docs
    const document = dr.documents[0];

    const { issuerAuth } = document.issuerSigned;
    const { deviceKey } = issuerAuth.decodedPayload.deviceKeyInfo;
    const { validityInfo, dsCertificate } = await this.verifyIssuerSignature(issuerAuth);

    await this.verifyDeviceSignature(document.deviceSigned.deviceAuth as DeviceAuth, {
      deviceKeyCoseKey: deviceKey,
      ephemeralPrivateKey: options.ephemeralReaderKey,
      sessionTranscriptBytes: options.encodedSessionTranscript,
      docType: document.docType,
      nameSpaces: document.deviceSigned.nameSpaces,
    });

    const data = dsCertificate && await this.verifyData(document, dsCertificate);

    return {
      isValid: this.getIsValid(),
      issuer: { nameSpaces: data?.issuerNameSpaces, validityInfo, dsCertificate },
      device: { nameSpaces: data?.deviceNameSpaces },
    };
  }
}
