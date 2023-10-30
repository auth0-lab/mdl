import { concat } from '../buffer_utils';
import { cborDecode } from '../cbor';

/**
 * Exports the COSE Key as a raw key.
 *
 * It's effectively the same than:
 *
 * crypto.subtle.exportKey('raw', importedJWK)
 *
 * Note: This only works for KTY = EC.
 *
 * @param {Map<number, Uint8Array | number>} key - The COSE Key
 * @returns {Uint8Array} - The raw key
 */
const COSEKeyToRAW = (
  key: Map<number, Uint8Array | number> | Uint8Array,
): Uint8Array => {
  let decodedKey: Map<number, Uint8Array | number>;
  if (key instanceof Uint8Array) {
    decodedKey = cborDecode(key);
  } else {
    decodedKey = key;
  }
  const kty = decodedKey.get(1);
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
  }

  // its a private key
  if (decodedKey.has(-4)) {
    return decodedKey.get(-4) as Uint8Array;
  }

  return concat(
    Uint8Array.from([0x04]),
    decodedKey.get(-2) as Uint8Array,
    decodedKey.get(-3) as Uint8Array,
  );
};

export default COSEKeyToRAW;
