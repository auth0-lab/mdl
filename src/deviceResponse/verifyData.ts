import crypto from 'node:crypto';
// eslint-disable-next-line import/no-unresolved
import Tagged from 'cbor/types/lib/tagged';
import { DeviceNameSpaces, MobileDocument, ValidatedIssuerNameSpaces } from './deviceResponse';
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
const verifyData = (mdoc: MobileDocument): {
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
  });

  return { issuerNameSpaces, deviceNameSpaces: mdoc.deviceSigned.nameSpaces };
};

export default verifyData;
