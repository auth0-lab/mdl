import { CoseProtectedHeaders, Header } from './cose';
import { cborDecode } from './cbor';
import CoseSign1 from './CoseSign1';
import CoseMac0 from './CoseMac0';

const headerFromMap = (
  map: Map<number, unknown>,
  key: number,
): unknown => {
  if (!map.has(key)) {
    throw new Error(`Map doesn't have key ${key}`);
  }

  return map.get(key);
};

const headerFromProtectedHeaders = (
  headers: CoseProtectedHeaders,
  key: number,
): unknown => {
  const map = cborDecode(headers, { mapsAsObjects: false });

  if (!(map instanceof Map)) {
    throw Error('Protected headers is not cbor encoded map');
  }

  return headerFromMap(map, key);
};

/**
 * Extract algorithm
 *
 * @param msg
 */
export const extractAlgorithm = (
  msg: CoseSign1 | CoseMac0,
): number => {
  const alg = headerFromProtectedHeaders(msg.protectedHeaders, Header.algorithm);

  if (typeof alg !== 'number') {
    throw new Error('Algorithm header is not a number');
  }

  return alg;
};

/**
 * Extract x5chain.
 * The certificate containing the public key belonging to the private key used to sign the MSO.
 *
 * @param msg
 */
export const extractX5Chain = (
  msg: CoseSign1,
): string[] => {
  // x5c MAY be followed by additional certificates, with each subsequent certificate being the one used to certify the previous one
  const x5chain = headerFromMap(msg.unprotectedHeaders, Header.x5chain);
  const certs = (Array.isArray(x5chain) ? x5chain : [x5chain]);

  if (certs.length < 1) {
    throw new Error('The x5chain element is empty');
  }

  return certs.map((cert) => {
    if (!Buffer.isBuffer(cert)) {
      throw new Error('The x5chain element is malformed');
    }

    return cert.toString('base64');
  });
};
