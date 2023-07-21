import { CoseProtectedHeaders, CoseUnprotectedHeaders } from '../cose';
import extractHeader from './extractHeader';
import Header from '../header';

/**
 * Extract algorithm
 *
 * @param msg
 */
export const extractAlgorithm = (
  protectedHeaders: CoseProtectedHeaders,
): number => {
  const alg = extractHeader(protectedHeaders, null, Header.algorithm);

  if (typeof alg !== 'number') {
    throw new Error('Algorithm header is not a number');
  }

  return alg;
};

/**
 * Extract x5chain.
 * The certificate containing the public key belonging to the private key used to sign the MSO.
 *
 * @param unprotectedHeaders
 */
export const extractX5Chain = (
  unprotectedHeaders: CoseUnprotectedHeaders,
): string => {
  const x5chain = extractHeader(null, unprotectedHeaders, Header.x5chain);

  if (!Buffer.isBuffer(x5chain)) {
    throw new Error('x5chain header is not a buffer');
  }

  return x5chain.toString('base64');
};
