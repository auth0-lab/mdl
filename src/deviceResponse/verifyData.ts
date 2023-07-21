import crypto from 'node:crypto';
// eslint-disable-next-line import/no-unresolved
import Tagged from 'cbor/types/lib/tagged';
import {
  DSCertificate, DeviceNameSpaces, MDL_NAMESPACE, MobileDocument, ValidatedIssuerNameSpaces,
} from './deviceResponse';
import { cborDecode, cborEncode } from '../cose/cbor';
import CoseSign1 from '../cose/CoseSign1';

const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as { [key: string]: string };

const validateDigest = (
  alg: string,
  digest: Buffer,
  elementValueToEvaluate: Tagged,
  namespace: string,
  elementIdentifier: string,
) => {
  const expectedDigest = crypto
    .createHash(alg)
    .update(cborEncode(elementValueToEvaluate))
    .digest();
  if (digest.compare(expectedDigest) !== 0) {
    throw new Error(
      `Invalid digest for element ${namespace}/${elementIdentifier}`,
    );
  }
};

/**
 * Confirm that the mdoc data has not changed since issuance.
 *
 * @param mdoc
 */
const verifyData = (mdoc: MobileDocument, dsCertificate: DSCertificate): {
  issuerNameSpaces: ValidatedIssuerNameSpaces, deviceNameSpaces: DeviceNameSpaces
} => {
  const issuerAuth = mdoc.issuerSigned.issuerAuth as CoseSign1;
  const { valueDigests, digestAlgorithm } = cborDecode(
    issuerAuth.getPayload(),
  ) as { valueDigests: { [x: string]: Map<number, Buffer> }, digestAlgorithm: string };
  const nameSpaces = mdoc.issuerSigned.nameSpaces || {};

  const issuerNameSpaces = {} as ValidatedIssuerNameSpaces;

  Object.keys(nameSpaces).forEach((ns) => {
    const digests = valueDigests[ns];
    if (!digests) {
      throw new Error(`Unable to find digests for namespace: ${ns}`);
    }

    if (!DIGEST_ALGS[digestAlgorithm]) {
      throw new Error(
        `Unsupported digest algorithm: ${digestAlgorithm}. Expected one of these algorithms: ${Object.keys(
          DIGEST_ALGS,
        ).join(', ')}`,
      );
    }

    issuerNameSpaces[ns] = {};

    nameSpaces[ns].forEach((ev, i) => {
      validateDigest(
        DIGEST_ALGS[digestAlgorithm],
        digests.get(ev.digestID),
        mdoc.raw.issuerSigned.nameSpaces[ns][i],
        ns,
        ev.elementIdentifier,
      );
      issuerNameSpaces[ns][ev.elementIdentifier] = ev.elementValue;
    });

    if (ns === MDL_NAMESPACE) {
      // if the `issuing_country` was retrieved, verify that the value matches the `countryName`
      // in the subject field within the DS certificate
      if (issuerNameSpaces[ns].issuing_country
        && issuerNameSpaces[ns].issuing_country !== dsCertificate.countryName) {
        throw new Error(`The 'issuing_country' (${issuerNameSpaces[ns].issuing_country}) must match the 'countryName' (${dsCertificate.countryName}) in the subject field within the DS certificate`);
      }

      // if the `issuing_jurisdiction` was retrieved, and `stateOrProvinceName` is
      // present in the subject field within the DS certificate, they must have the same value
      if (issuerNameSpaces[ns].issuing_jurisdiction
        && dsCertificate.stateOrProvinceName
        && issuerNameSpaces[ns].issuing_jurisdiction !== dsCertificate.stateOrProvinceName) {
        throw new Error(`The 'issuing_jurisdiction' (${issuerNameSpaces[ns].issuing_jurisdiction}) must match the 'stateOrProvinceName' (${dsCertificate.stateOrProvinceName}) in the subject field within the DS certificate`);
      }
    }
  });

  return { issuerNameSpaces, deviceNameSpaces: mdoc.deviceSigned.nameSpaces };
};

export default verifyData;
