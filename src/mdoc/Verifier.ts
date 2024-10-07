import { compareVersions } from 'compare-versions';
import { X509Certificate } from '@peculiar/x509';
import { importX509, JWK, KeyLike } from 'jose';
import { Buffer } from 'buffer';
import { COSEKeyToJWK, Sign1, importCOSEKey } from 'cose-kit';
import crypto from 'uncrypto';
import { MDoc } from './model/MDoc';

import {
  calculateEphemeralMacKey,
  calculateDeviceAutenticationBytes,
  sha256,
} from './utils';

import {
  ValidatedIssuerNameSpaces,
  DiagnosticInformation,
} from './model/types';
import { UserDefinedVerificationCallback, VerificationAssessment, buildCallback, onCatCheck } from './checkCallback';

import { parse } from './parser';
import IssuerAuth from './model/IssuerAuth';
import { IssuerSignedDocument } from './model/IssuerSignedDocument';
import { DeviceSignedDocument } from './model/DeviceSignedDocument';
import COSEKeyToRAW from '../cose/coseKey';
import { cborEncode, DataItem } from '../cbor';

const MDL_NAMESPACE = 'org.iso.18013.5.1';

const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as { [key: string]: string };

export class Verifier {
  /**
   * The encoded session transcript to use for verification.
   * @see {@link usingSessionTranscriptBytes}
   * @see {@link usingSessionTranscriptForOID4VP}
   * @see {@link usingSessionTranscriptForWebAPI}
   */
  #sessionTranscriptBytes: Promise<Buffer> | Buffer;

  /**
   * The raw private part of the ephemeral reader key.
   * @see {@link usingEphemeralReaderKey}
   */
  #ephemeralReaderKey: Uint8Array;

  #disableCertificateChainValidation: boolean = false;

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
    document: IssuerSignedDocument | DeviceSignedDocument,
    onCheckCbk: UserDefinedVerificationCallback,
  ) {
    const onCheck = onCatCheck(onCheckCbk, 'DEVICE_AUTH');

    if (!(document instanceof DeviceSignedDocument)) {
      onCheck({
        status: 'FAILED',
        check: 'The document is not signed by the device.',
      });
      return;
    }
    const { deviceAuth, nameSpaces } = document.deviceSigned;
    const { docType } = document;
    const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload;
    const { deviceKey: deviceKeyCoseKey } = deviceKeyInfo || {};

    // Prevent cloning of the mdoc and mitigate man in the middle attacks
    if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
      onCheck({
        status: 'FAILED',
        check: 'Device Auth must contain a deviceSignature or deviceMac element',
      });
      return;
    }

    if (!this.#sessionTranscriptBytes) {
      onCheck({
        status: 'FAILED',
        check: 'Set Session Transcript Bytes with .usingSessionTranscriptForWepAPI, .usingSessionTranscriptForOID4VP or .usingSessionTranscriptBytes, aborting device signature check',
      });
      return;
    }

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      await this.#sessionTranscriptBytes,
      docType,
      nameSpaces,
    );

    if (!deviceKeyCoseKey) {
      onCheck({
        status: 'FAILED',
        check: 'Issuer signature must contain the device key.',
        reason: 'Unable to verify deviceAuth signature: missing device key in issuerAuth',
      });
      return;
    }

    if (deviceAuth.deviceSignature) {
      const deviceKey = await importCOSEKey(deviceKeyCoseKey);

      // ECDSA/EdDSA authentication
      try {
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
      status: this.#ephemeralReaderKey ? 'PASSED' : 'FAILED',
      check: 'Set Ephemeral private key with .usingEphemeralReaderKey using MAC authentication',
    });
    if (!this.#ephemeralReaderKey) { return; }

    try {
      const deviceKeyRaw = COSEKeyToRAW(deviceKeyCoseKey);
      const ephemeralMacKey = await calculateEphemeralMacKey(
        this.#ephemeralReaderKey,
        deviceKeyRaw,
        await this.#sessionTranscriptBytes,
      );

      const isValid = await deviceAuth.deviceMac.verify(
        ephemeralMacKey,
        undefined,
        deviceAuthenticationBytes,
      );

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
    mdoc: IssuerSignedDocument,
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
        const isValid = await ev.isValid(ns, issuerAuth);
        return { ev, ns, isValid };
      }));

      verifications.filter((v) => v.isValid).forEach((v) => {
        onCheck({
          status: 'PASSED',
          check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
        });
      });

      verifications.filter((v) => !v.isValid).forEach((v) => {
        onCheck({
          status: 'FAILED',
          check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
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
            .some((v) => !v.isValid || !v.ev.matchCertificate(ns, issuerAuth));

          onCheck({
            status: isCountryInvalid ? 'FAILED' : 'PASSED',
            check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
            reason: isCountryInvalid ?
              `The 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) must match the 'countryName' (${issuerAuth.countryName}) in the subject field within the issuer certificate` :
              undefined,
          });

          const isJurisdictionInvalid = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
            .some((v) => !v.isValid || !v.ev.matchCertificate(ns, issuerAuth));

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
   * Set the session transcript data to use for the verification.
   *
   * This is arbitrary and should match the session transcript as it was calculated by the mdoc app (ie, wallet).
   * The transcript must be a CBOR encoded DataItem of an array, there is no further requirement.
   *
   * Example: `usingSessionTranscriptBytes(cborEncode(DataItem.fromData([a,b,c])))` where `a`, `b` and `c` can be anything including `null`.
   *
   * It is preferable to use {@link usingSessionTranscriptForOID4VP} or {@link usingSessionTranscriptForWebAPI} when possible.
   *
   * @param {Buffer | Promise<Buffer>} sessionTranscriptBytes - The sessionTranscriptBytes data to use in the session transcript.
   * @returns {Verifier}
   */
  public usingSessionTranscriptBytes(sessionTranscriptBytes: Buffer | Promise<Buffer>): Verifier {
    if (this.#sessionTranscriptBytes) {
      throw new Error(
        'A session transcript has already been set, either with .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes',
      );
    }
    this.#sessionTranscriptBytes = sessionTranscriptBytes;
    return this;
  }

  /**
   * Set the session transcript data to use for the verification as defined in ISO/IEC 18013-7 in Annex B (OID4VP), 2024 draft.
   *
   * This should match the session transcript as it was calculated by the mdoc app.
   *
   * @param {string} mdocGeneratedNonce - The mdoc-generated nonce, taken from the `apu` parameter in the Authorization Response
   * @param {string} clientId - The client_id Authorization Request parameter from the Authorization Request Object.
   * @param {string} responseUri - The response_uri Authorization Request parameter from the Authorization Request Object.
   * @param {string} verifierGeneratedNonce - The nonce taken from the `apv` parameter in the Authorization Response (it should match the `nonce` sent in the Authorization Request parameter from the Authorization Request Object).
   * @returns {Verifier}
   */
  public usingSessionTranscriptForOID4VP(
    mdocGeneratedNonce: string,
    clientId: string,
    responseUri: string,
    verifierGeneratedNonce: string,
  ): Verifier {
    this.usingSessionTranscriptBytes(
      this.#oid4vptranscript(mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce),
    );
    return this;
  }

  async #oid4vptranscript(
    mdocGeneratedNonce: string,
    clientId: string,
    responseUri: string,
    verifierGeneratedNonce: string,
  ) {
    return cborEncode(
      DataItem.fromData([
        null, // deviceEngagementBytes
        null, // eReaderKeyBytes
        [
          await sha256(cborEncode([clientId, mdocGeneratedNonce])),
          await sha256(cborEncode([responseUri, mdocGeneratedNonce])),
          verifierGeneratedNonce,
        ],
      ]),
    );
  }

  /**
   * Set the session transcript data to use for the verification as defined in ISO/IEC 18013-7 in Annex A (Web API), 2024 draft.
   *
   * This should match the session transcript as it will be calculated by the mdoc app.
   *
   * @param {Buffer} deviceEngagementBytes - The device engagement, encoded as a Tagged 24 cbor
   * @param {Buffer} readerEngagementBytes - The reader engagement, encoded as a Tagged 24 cbor
   * @param {Buffer} eReaderKeyBytes - The reader ephemeral public key as a COSE Key, encoded as a Tagged 24 cbor
   * @returns {Verifier}
   */
  public usingSessionTranscriptForWebAPI(
    deviceEngagementBytes: Buffer,
    readerEngagementBytes: Buffer,
    eReaderKeyBytes: Buffer,
  ): Verifier {
    this.usingSessionTranscriptBytes(
      sha256(readerEngagementBytes).then(
        (readerEngagementBytesHash) => cborEncode(
          DataItem.fromData([
            new DataItem({ buffer: deviceEngagementBytes }),
            new DataItem({ buffer: eReaderKeyBytes }),
            readerEngagementBytesHash,
          ]),
        ),
      ),
    );
    return this;
  }

  /**
   * @param {Buffer} ephemeralReaderKey - The private part of the ephemeral key used in the session where the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC method for device authentication.
   * @returns {Verifier}
   */
  public usingEphemeralReaderKey(ephemeralReaderKey: Uint8Array): Verifier {
    this.#ephemeralReaderKey = ephemeralReaderKey;
    return this;
  }

  /**
   * Disables the certificate validation
   * @returns {Verifier}
   */
  public disableCertificateChainValidation(): Verifier {
    this.#disableCertificateChainValidation = true;
    return this;
  }

  /**
   * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
   *
   * @param encodedDeviceResponse
   */
  async verify(
    encodedDeviceResponse: Uint8Array,
    onCheck?: UserDefinedVerificationCallback,
  ): Promise<MDoc> {
    const onCheckCbk = buildCallback(onCheck);

    const dr = parse(encodedDeviceResponse);

    onCheckCbk({
      status: dr.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    });

    onCheckCbk({
      status: compareVersions(dr.version, '1.0') >= 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response version must be 1.0 or greater',
      category: 'DOCUMENT_FORMAT',
    });

    onCheckCbk({
      status: dr.documents && dr.documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must include at least one document.',
      category: 'DOCUMENT_FORMAT',
    });

    for (const document of dr.documents) {
      const { issuerAuth } = document.issuerSigned;
      await this.verifyIssuerSignature(issuerAuth, this.#disableCertificateChainValidation, onCheckCbk);

      await this.verifyDeviceSignature(document, onCheckCbk);

      await this.verifyData(document, onCheckCbk);
    }

    return dr;
  }

  async getDiagnosticInformation(
    encodedDeviceResponse: Buffer,
  ): Promise<DiagnosticInformation> {
    const dr: VerificationAssessment[] = [];
    const decoded = await this.verify(encodedDeviceResponse, (check) => dr.push(check));

    const document = decoded.documents[0];
    const { issuerAuth } = document.issuerSigned;
    const issuerCert = issuerAuth.x5chain &&
      issuerAuth.x5chain.length > 0 &&
      new X509Certificate(issuerAuth.x5chain[0]);

    const attributes = (await Promise.all(Object.keys(document.issuerSigned.nameSpaces).map(async (ns) => {
      const items = document.issuerSigned.nameSpaces[ns];
      return Promise.all(items.map(async (item) => {
        const isValid = await item.isValid(ns, issuerAuth);
        return {
          ns,
          id: item.elementIdentifier,
          value: item.elementValue,
          isValid,
          matchCertificate: item.matchCertificate(ns, issuerAuth),
        };
      }));
    }))).flat();

    const deviceAttributes = document instanceof DeviceSignedDocument ?
      Object.entries(document.deviceSigned.nameSpaces).map(([ns, items]) => {
        return Object.entries(items).map(([id, value]) => {
          return {
            ns,
            id,
            value,
          };
        });
      }).flat() : undefined;

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
      deviceSignature: document instanceof DeviceSignedDocument ? {
        alg: document.deviceSigned.deviceAuth.deviceSignature?.algName ??
          document.deviceSigned.deviceAuth.deviceMac?.algName,
        isValid: dr
          .filter((check) => check.category === 'DEVICE_AUTH')
          .every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'DEVICE_AUTH' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
      } : undefined,
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
