import { compareVersions } from 'compare-versions';
import { X509Certificate } from '@peculiar/x509';
import { importX509, JWK, KeyLike } from 'jose';
import { Buffer } from 'buffer';
import { COSEKeyToJWK, Mac0, Sign1, importDecodedCOSEKey } from 'cose';
import crypto from 'uncrypto';
import coseKeyMapToBuffer from '../cose/coseKey';

import {
  calculateEphemeralMacKey,
  calculateDeviceAutenticationBytes,
} from './utils';

import {
  DeviceAuth,
  MobileDocument,
  ValidatedIssuerNameSpaces,
  DeviceResponse,
  DiagnosticInformation,
} from './types';
import { UserDefinedVerificationCallback, VerificationAssessment, buildCallback, onCatCheck } from './checkCallback';

import { parse } from './parser';
import IssuerAuth from './IssuerAuth';

const MDL_NAMESPACE = 'org.iso.18013.5.1';

const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as { [key: string]: string };

export class DeviceResponseVerifier {
  /**
   *
   * @param issuersRootCertificates The IACA root certificates list of the supported issuers.
   */
  constructor(public readonly issuersRootCertificates: string[]) { }

  private async verifyIssuerSignature(
    issuerAuth: IssuerAuth,
    disableCertificateChainValidation: boolean,
    onCheckG: UserDefinedVerificationCallback,
  ) {
    const onCheck = onCatCheck(onCheckG, 'ISSUER_AUTH');
    const { certificate, countryName } = issuerAuth;
    const verificationKey: KeyLike | undefined = certificate ? (await importX509(
      certificate.toString(),
      issuerAuth.algName,
    )) : undefined;

    if (!disableCertificateChainValidation) {
      try {
        await issuerAuth.verifyX509Chain(this.issuersRootCertificates);
        onCheck({
          status: 'PASSED',
          check: 'Issuer certificate must be valid',
        });
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Issuer certificate must be valid',
          reason: err.message,
        });
      }
    }

    const verificationResult = verificationKey && await issuerAuth.verify(verificationKey);
    onCheck({
      status: verificationResult ? 'PASSED' : 'FAILED',
      check: 'Issuer signature must be valid',
    });

    // Validity
    const { validityInfo } = issuerAuth.decodedPayload;
    const now = new Date();

    onCheck({
      status: certificate && validityInfo && (validityInfo.signed < certificate.notBefore || validityInfo.signed > certificate.notAfter) ? 'FAILED' : 'PASSED',
      check: 'The MSO signed date must be within the validity period of the certificate',
      reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${certificate.notBefore.toUTCString()} to ${certificate.notAfter.toUTCString()})`,
    });

    onCheck({
      status: validityInfo && (now < validityInfo.validFrom || now > validityInfo.validUntil) ? 'FAILED' : 'PASSED',
      check: 'The MSO must be valid at the time of verification',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
    });

    onCheck({
      status: countryName ? 'PASSED' : 'FAILED',
      check: 'Country name (C) must be present in the issuer certificate\'s subject distinguished name',
    });
  }

  private async verifyDeviceSignature(
    deviceAuth: DeviceAuth,
    options: {
      deviceKeyCoseKey: Map<number, number | Uint8Array> | undefined;
      ephemeralPrivateKey?: Buffer;
      sessionTranscriptBytes?: Buffer;
      docType: string;
      nameSpaces: Map<string, Map<string, any>>;
      onCheck: UserDefinedVerificationCallback;
    },
  ) {
    const onCheck = onCatCheck(options.onCheck, 'DEVICE_AUTH');

    // Prevent cloning of the mdoc and mitigate man in the middle attacks
    if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
      onCheck({
        status: 'FAILED',
        check: 'Device Auth must contain a deviceSignature or deviceMac element',
      });
      return;
    }

    if (!options.sessionTranscriptBytes) {
      onCheck({
        status: 'FAILED',
        check: 'Session Transcript Bytes missing from options, aborting device signature check',
      });
      return;
    }

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      options.sessionTranscriptBytes,
      options.docType,
      options.nameSpaces,
    );

    if (!options.deviceKeyCoseKey) {
      onCheck({
        status: 'FAILED',
        check: 'Issuer signature must contain the device key.',
        reason: 'Unable to verify deviceAuth signature: missing device key in issuerAuth',
      });
      return;
    }

    if (deviceAuth.deviceSignature) {
      // ECDSA/EdDSA authentication
      try {
        const deviceKey = await importDecodedCOSEKey(options.deviceKeyCoseKey);

        const ds = deviceAuth.deviceSignature;

        const verificationResult = await new Sign1(
          ds.protectedHeaders,
          ds.unprotectedHeaders,
          deviceAuthenticationBytes,
          ds.signature,
        ).verify(deviceKey);

        onCheck({
          status: verificationResult ? 'PASSED' : 'FAILED',
          check: 'Device signature must be valid',
        });
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Device signature must be valid',
          reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err.message}`,
        });
      }
      return;
    }

    // MAC authentication
    onCheck({
      status: deviceAuth.deviceMac ? 'PASSED' : 'FAILED',
      check: 'Device MAC must be present when using MAC authentication',
    });
    if (!deviceAuth.deviceMac) { return; }

    onCheck({
      status: deviceAuth.deviceMac.hasSupportedAlg() ? 'PASSED' : 'FAILED',
      check: 'Device MAC must use alg 5 (HMAC 256/256)',
    });
    if (!deviceAuth.deviceMac.hasSupportedAlg()) { return; }

    onCheck({
      status: options.ephemeralPrivateKey ? 'PASSED' : 'FAILED',
      check: 'Ephemeral private key must be present when using MAC authentication',
    });
    if (!options.ephemeralPrivateKey) { return; }

    try {
      const deviceKey = coseKeyMapToBuffer(options.deviceKeyCoseKey);
      const ephemeralMacKey = await calculateEphemeralMacKey(
        deviceKey,
        options.ephemeralPrivateKey,
        options.sessionTranscriptBytes,
      );

      const isValid = await Mac0.create(
        { alg: 'HS256' },
        {},
        deviceAuthenticationBytes,
        ephemeralMacKey,
      ).then((mac) => deviceAuth.deviceMac && mac.areEqual(deviceAuth.deviceMac));

      onCheck({
        status: isValid ? 'PASSED' : 'FAILED',
        check: 'Device MAC must be valid',
      });
    } catch (err) {
      onCheck({
        status: 'FAILED',
        check: 'Device MAC must be valid',
        reason: `Unable to verify deviceAuth MAC: ${err.message}`,
      });
    }
  }

  private async verifyData(
    mdoc: MobileDocument,
    onCheckG: UserDefinedVerificationCallback,
  ) {
    // Confirm that the mdoc data has not changed since issuance
    const { issuerAuth } = mdoc.issuerSigned;
    const { valueDigests, digestAlgorithm } = issuerAuth.decodedPayload;
    const onCheck = onCatCheck(onCheckG, 'DATA_INTEGRITY');

    onCheck({
      status: digestAlgorithm && DIGEST_ALGS[digestAlgorithm] ? 'PASSED' : 'FAILED',
      check: 'Issuer Auth must include a supported digestAlgorithm element',
    });

    const nameSpaces = mdoc.issuerSigned.nameSpaces || {};
    const issuerNameSpaces: ValidatedIssuerNameSpaces = {};

    await Promise.all(Object.keys(nameSpaces).map(async (ns) => {
      onCheck({
        status: valueDigests.has(ns) ? 'PASSED' : 'FAILED',
        check: `Issuer Auth must include digests for namespace: ${ns}`,
      });

      const verifications = await Promise.all(nameSpaces[ns].map(async (ev) => {
        const isValid = await ev.isValid();
        return { ev, ns, isValid };
      }));

      verifications.filter((v) => v.isValid).forEach((v) => {
        onCheck({
          status: 'PASSED',
          check: `The value of ${ns}/${v.ev.elementIdentifier} must match the digest in the issuerAuth element`,
        });
      });

      verifications.filter((v) => !v.isValid).forEach((v) => {
        onCheck({
          status: 'FAILED',
          check: `The value of ${ns}/${v.ev.elementIdentifier} must match the digest in the issuerAuth element`,
        });
      });

      if (ns === MDL_NAMESPACE) {
        const issuer = issuerAuth.certificate.issuerName;
        if (!issuer) {
          onCheck({
            status: 'FAILED',
            check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
            reason: "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
          });
        } else {
          const isCountryInvalid = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
            .some((v) => !v.isValid || !v.ev.matchCertificate());

          onCheck({
            status: isCountryInvalid ? 'FAILED' : 'PASSED',
            check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
            reason: isCountryInvalid ?
              `The 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) must match the 'countryName' (${issuerAuth.countryName}) in the subject field within the issuer certificate` :
              undefined,
          });

          const isJurisdictionInvalid = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
            .some((v) => !v.isValid || !v.ev.matchCertificate());

          onCheck({
            status: isJurisdictionInvalid ? 'FAILED' : 'PASSED',
            check: "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
            reason: isJurisdictionInvalid ?
              `The 'issuing_jurisdiction' (${issuerNameSpaces[ns].issuing_jurisdiction}) must match the 'stateOrProvinceName' (${issuerAuth.stateOrProvince}) in the subject field within the issuer certificate` :
              undefined,
          });
        }
      }
    }));
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
    options: {
      encodedSessionTranscript?: Buffer,
      ephemeralReaderKey?: Buffer,
      disableCertificateChainValidation?: boolean,
      onCheck?: UserDefinedVerificationCallback
    } = {},
  ): Promise<DeviceResponse> {
    const onCheck = buildCallback(options.onCheck);

    const dr = await parse(encodedDeviceResponse);

    onCheck({
      status: dr.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    });

    onCheck({
      status: compareVersions(dr.version, '1.0') >= 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response version must be 1.0 or greater',
      category: 'DOCUMENT_FORMAT',
    });

    onCheck({
      status: dr.documents && dr.documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must include at least one document.',
      category: 'DOCUMENT_FORMAT',
    });

    for (const document of dr.documents) {
      const { issuerAuth } = document.issuerSigned;
      const { deviceKeyInfo } = issuerAuth.decodedPayload;
      await this.verifyIssuerSignature(issuerAuth, options.disableCertificateChainValidation, onCheck);

      await this.verifyDeviceSignature(document.deviceSigned.deviceAuth, {
        deviceKeyCoseKey: deviceKeyInfo?.deviceKey,
        ephemeralPrivateKey: options.ephemeralReaderKey,
        sessionTranscriptBytes: options.encodedSessionTranscript,
        docType: document.docType,
        nameSpaces: document.deviceSigned.nameSpaces,
        onCheck,
      });

      await this.verifyData(document, onCheck);
    }

    return dr;
  }

  async getDiagnosticInformation(
    encodedDeviceResponse: Buffer,
    options: {
      encodedSessionTranscript?: Buffer,
      ephemeralReaderKey?: Buffer,
      disableCertificateChainValidation?: boolean,
    },
  ): Promise<DiagnosticInformation> {
    const dr: VerificationAssessment[] = [];
    const decoded = await this.verify(
      encodedDeviceResponse,
      {
        ...options,
        onCheck: (check) => dr.push(check),
      },
    );

    const document = decoded.documents[0];
    const issuerCert = document?.issuerSigned.issuerAuth.x5chain &&
      document.issuerSigned.issuerAuth.x5chain.length > 0 &&
      new X509Certificate(document.issuerSigned.issuerAuth.x5chain[0]);

    const attributes = (await Promise.all(Object.keys(document.issuerSigned.nameSpaces).map(async (ns) => {
      const items = document.issuerSigned.nameSpaces[ns];
      return Promise.all(items.map(async (item) => {
        const isValid = await item.isValid();
        return {
          ns,
          id: item.elementIdentifier,
          value: item.elementValue,
          isValid,
          matchCertificate: item.matchCertificate(),
        };
      }));
    }))).flat();

    const deviceAttributes = Array.from(document.deviceSigned.nameSpaces.entries()).map(([ns, items]) => {
      return Array.from(items.entries()).map(([id, value]) => {
        return {
          ns,
          id,
          value,
        };
      });
    }).flat();
    let deviceKey: JWK;

    if (document?.issuerSigned.issuerAuth) {
      const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload;
      if (deviceKeyInfo?.deviceKey) {
        deviceKey = COSEKeyToJWK(deviceKeyInfo.deviceKey);
      }
    }
    const disclosedAttributes = attributes.filter((attr) => attr.isValid).length;
    const totalAttributes = Array.from(
      document
        .issuerSigned
        .issuerAuth
        .decodedPayload
        .valueDigests
        .entries(),
    ).reduce((prev, [, digests]) => prev + digests.size, 0);

    return {
      general: {
        version: decoded.version,
        type: 'DeviceResponse',
        status: decoded.status,
        documents: decoded.documents.length,
      },
      validityInfo: document.issuerSigned.issuerAuth.decodedPayload.validityInfo,
      issuerCertificate: issuerCert ? {
        subjectName: issuerCert.subjectName.toString(),
        pem: issuerCert.toString(),
        notBefore: issuerCert.notBefore,
        notAfter: issuerCert.notAfter,
        serialNumber: issuerCert.serialNumber,
        thumbprint: Buffer.from(await issuerCert.getThumbprint(crypto)).toString('hex'),
      } : undefined,
      issuerSignature: {
        alg: document.issuerSigned.issuerAuth.algName,
        isValid: dr
          .filter((check) => check.category === 'ISSUER_AUTH')
          .every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'ISSUER_AUTH' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
        digests: Object.fromEntries(
          Array.from(
            document
              .issuerSigned
              .issuerAuth
              .decodedPayload
              .valueDigests
              .entries(),
          ).map(([ns, digests]) => [ns, digests.size]),
        ),
      },
      deviceKey: {
        jwk: deviceKey,
      },
      deviceSignature: {
        alg: document.deviceSigned.deviceAuth.deviceSignature?.algName ??
          document.deviceSigned.deviceAuth.deviceMac?.algName,
        isValid: dr
          .filter((check) => check.category === 'DEVICE_AUTH')
          .every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'DEVICE_AUTH' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
      },
      dataIntegrity: {
        disclosedAttributes: `${disclosedAttributes} of ${totalAttributes}`,
        isValid: dr
          .filter((check) => check.category === 'DATA_INTEGRITY')
          .every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'DATA_INTEGRITY' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
      },
      attributes,
      deviceAttributes,
    };
  }
}
