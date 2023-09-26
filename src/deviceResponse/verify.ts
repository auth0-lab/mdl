import { compareVersions } from 'compare-versions';
import { X509Certificate } from '@peculiar/x509';
import type { KeyLike } from 'jose';
import { Mac0, Sign1, importDecodedCOSEKey } from 'cose';
import { areEqual } from '../buffer_utils';

import coseKeyMapToBuffer from '../cose/coseKey';
import {
  calculateEphemeralMacKey,
  calculateDeviceAutenticationBytes,
} from './utils';

import {
  DeviceAuth,
  DSCertificate,
  MobileDocument,
  ValidatedIssuerNameSpaces,
  NameSpaces,
  DeviceResponse,
} from './types';
import { UserDefinedVerificationCallback, buildCallback, onCatCheck } from './checkCallback';

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

  private async verifyIssuerSignature(msg: IssuerAuth, onCheckG: UserDefinedVerificationCallback):
    Promise<{ dsCertificate: DSCertificate }> {
    const onCheck = onCatCheck(onCheckG, 'ISSUER_AUTH');
    let verificationKey: KeyLike;
    let issuerCert: X509Certificate;

    try {
      const x509Result = await msg.verifyX509Chain(this.issuersRootCertificates);
      verificationKey = x509Result.publicKey;
      issuerCert = new X509Certificate(x509Result.raw);
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
      throw new Error('Issuer certificate must be valid');
    }

    // Verify signature
    const verificationResult = await msg.verify(verificationKey);

    onCheck({
      status: verificationResult ? 'PASSED' : 'FAILED',
      check: 'Issuer signature must be valid',
    });

    // Validity
    const { validityInfo } = msg.decodedPayload;
    const now = new Date();

    onCheck({
      status: validityInfo.signed < issuerCert.notBefore || validityInfo.signed > issuerCert.notAfter ? 'FAILED' : 'PASSED',
      check: 'The MSO signed date must be within the validity period of the certificate',
      reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${issuerCert.notBefore.toUTCString()} to ${issuerCert.notAfter.toUTCString()})`,
    });

    onCheck({
      status: now < validityInfo.validFrom || now > validityInfo.validUntil ? 'FAILED' : 'PASSED',
      check: 'The MSO must be valid at the time of verification',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
    });

    // countryName is mandatory, stateOrProvinceName is optional
    const stateOrProvinceName = issuerCert.issuerName.getField('ST')[0];
    const countryName = issuerCert.issuerName.getField('C')[0];
    onCheck({
      status: countryName ? 'PASSED' : 'FAILED',
      check: 'Country name (C) must be present in the issuer certificate\'s subject distinguished name',
    });

    return {
      dsCertificate: {
        issuer: { countryName, stateOrProvinceName },
        validity: { notBefore: issuerCert.notBefore, notAfter: issuerCert.notAfter },
      },
    };
  }

  private async verifyDeviceSignature(
    deviceAuth: DeviceAuth,
    options: {
      deviceKeyCoseKey: Map<number, number | Uint8Array> | undefined;
      ephemeralPrivateKey?: Buffer;
      sessionTranscriptBytes?: Buffer;
      docType: string;
      nameSpaces: NameSpaces;
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
          ds.payload && ds.payload.byteLength > 0 ? ds.payload : deviceAuthenticationBytes,
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
    dsCertificate: DSCertificate,
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
      const digests = valueDigests.get(ns) as Map<number, Uint8Array>;
      onCheck({
        status: digests ? 'PASSED' : 'FAILED',
        check: `Issuer Auth must include digests for namespace: ${ns}`,
      });

      issuerNameSpaces[ns] = {};

      await Promise.all(nameSpaces[ns].map(async (ev) => {
        const digest = digests.get(ev.digestID);
        const expectedDigest = await ev.calculateDigest(digestAlgorithm);
        const isValid = digest && areEqual(digest, new Uint8Array(expectedDigest));

        onCheck({
          status: isValid ? 'PASSED' : 'FAILED',
          check: `Issuer Auth must include a valid digest for ${ns}/${ev.elementIdentifier} element`,
        });
        if (isValid) {
          issuerNameSpaces[ns][ev.elementIdentifier] = ev.elementValue;
        }
      }));

      if (ns === MDL_NAMESPACE) {
        const issuingCountryIsValid = typeof issuerNameSpaces[ns].issuing_country === 'undefined' ||
          issuerNameSpaces[ns].issuing_country === dsCertificate.issuer.countryName ? 'PASSED' : 'FAILED';
        // if the `issuing_country` was retrieved, verify that the value matches the `countryName` in the subject field within the DS certificate
        onCheck({
          status: issuingCountryIsValid,
          check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
          reason: issuingCountryIsValid ? undefined : `The 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) must match the 'countryName' (${dsCertificate.issuer.countryName}) in the subject field within the issuer certificate`,
        });

        const issuingJurisdictionIsValid = typeof issuerNameSpaces[ns].issuing_jurisdiction === 'undefined' ||
          typeof dsCertificate.issuer.stateOrProvinceName === 'undefined' ||
          issuerNameSpaces[ns].issuing_jurisdiction === dsCertificate.issuer.stateOrProvinceName ? 'PASSED' : 'FAILED';
        // if the `issuing_jurisdiction` was retrieved, and `stateOrProvinceName` is present in the subject field within the DS certificate, they must have the same value
        onCheck({
          status: issuingJurisdictionIsValid,
          check: "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
          reason: issuingJurisdictionIsValid ? undefined : `The 'issuing_jurisdiction' (${issuerNameSpaces[ns].issuing_jurisdiction}) must match the 'stateOrProvinceName' (${dsCertificate.issuer.stateOrProvinceName}) in the subject field within the issuer certificate`,
        });
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
      const { dsCertificate } = await this.verifyIssuerSignature(issuerAuth, onCheck);

      await this.verifyDeviceSignature(document.deviceSigned.deviceAuth, {
        deviceKeyCoseKey: deviceKeyInfo?.deviceKey,
        ephemeralPrivateKey: options.ephemeralReaderKey,
        sessionTranscriptBytes: options.encodedSessionTranscript,
        docType: document.docType,
        nameSpaces: document.deviceSigned.nameSpaces,
        onCheck,
      });

      if (dsCertificate) {
        await this.verifyData(document, dsCertificate, onCheck);
      }
    }

    return dr;
  }
}
