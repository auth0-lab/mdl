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
  const map = cborDecode(headers);

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
  const alg = headerFromProtectedHeaders(msg.getProtectedHeaders(), Header.algorithm);

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
): string => {
  const x5chain = headerFromMap(msg.getUnprotectedHeaders(), Header.x5chain);

  if (!Buffer.isBuffer(x5chain)) {
    throw new Error('x5chain header is not a buffer');
  }

  return x5chain.toString('base64');
};
