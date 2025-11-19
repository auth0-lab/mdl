import * as pkijs from 'pkijs';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import * as webcrypto from 'uncrypto';
import { Buffer } from 'buffer';
import hkdf from '@panva/hkdf';
import { COSEKeyToJWK } from 'cose-kit';

import { cborEncode, cborDecode } from '../cbor';
import { DataItem } from '../cbor/DataItem';
import COSEKeyToRAW from '../cose/coseKey';
import { SupportedAlgs } from './model/types';

const { subtle } = webcrypto;

pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto', crypto: webcrypto, subtle }));

export const hmacSHA256 = async (
  key: ArrayBuffer,
  data: ArrayBuffer,
): Promise<ArrayBuffer> => {
  const saltHMACKey = await subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );

  const hmac = await subtle.sign('HMAC', saltHMACKey, data);

  return hmac;
};

/**
 * Calculates the ephemeral mac key for the device authentication.
 *
 * There are two cases for this function:
 * 1. SDeviceKey.Priv and EReaderKey.Pub for the mdoc
 * 2. EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader
 *
 * @param {Uint8Array} privateKey - The private key of the current party (COSE)
 * @param {Uint8Array} publicKey - The public key of the other party, (COSE)
 * @param {Uint8Array} sessionTranscriptBytes - The session transcript bytes
 * @returns {Uint8Array} - The ephemeral mac key
 */
export const calculateEphemeralMacKey = async (
  privateKey: Uint8Array | Map<number, Uint8Array | number>,
  publicKey: Uint8Array | Map<number, Uint8Array | number>,
  sessionTranscriptBytes: Uint8Array,
): Promise<Uint8Array> => {
  const { kty, crv } = COSEKeyToJWK(privateKey);
  const privkey = COSEKeyToRAW(privateKey); // only d
  const pubkey = COSEKeyToRAW(publicKey); // 0x04 || x || y
  let ikm;
  if ((kty === 'EC')) {
    if (crv === 'P-256') {
      ikm = p256
        .getSharedSecret(
          Buffer.from(privkey).toString('hex'),
          Buffer.from(pubkey).toString('hex'),
          true,
        )
        .slice(1);
    } else if (crv === 'P-384') {
      ikm = p384
        .getSharedSecret(
          Buffer.from(privkey).toString('hex'),
          Buffer.from(pubkey).toString('hex'),
          true,
        )
        .slice(1);
    } else if (crv === 'P-521') {
      ikm = p521
        .getSharedSecret(
          Buffer.from(privkey).toString('hex'),
          Buffer.from(pubkey).toString('hex'),
          true,
        )
        .slice(1);
    } else {
      throw new Error(`unsupported EC curve: ${crv}`);
    }
  } else {
    throw new Error(`unsupported key type: ${kty}`);
  }
  const salt = new Uint8Array(await subtle.digest('SHA-256', sessionTranscriptBytes));
  const info = Buffer.from('EMacKey', 'utf-8');
  const result = await hkdf('sha256', ikm, salt, info, 32);
  return result;
};

export const calculateDeviceAutenticationBytes = (
  sessionTranscript: Uint8Array | any,
  docType: string,
  nameSpaces: Record<string, Record<string, any>>,
): Uint8Array => {
  let decodedSessionTranscript: any;
  if (sessionTranscript instanceof Uint8Array) {
    // assume is encoded in a DataItem
    decodedSessionTranscript = (cborDecode(sessionTranscript) as DataItem).data;
  } else {
    decodedSessionTranscript = sessionTranscript;
  }

  const nameSpacesAsMap = new Map(Object.entries(nameSpaces).map(([ns, items]) => [ns, new Map(Object.entries(items))]));
  const encode = DataItem.fromData([
    'DeviceAuthentication',
    decodedSessionTranscript,
    docType,
    DataItem.fromData(nameSpacesAsMap),
  ]);

  const result = cborEncode(encode);

  return result;
};

export function getRandomBytes(len: number) {
  return webcrypto.getRandomValues(new Uint8Array(len));
}

export function fromPEM(pem: string): Uint8Array {
  const base64 = pem.replace(/-{5}(BEGIN|END) .*-{5}/gm, '').replace(/\s/gm, '');
  return Buffer.from(base64, 'base64');
}

/**
 * Maps elliptic curve identifiers to signature algorithms according to ISO/IEC 18013-5.
 * 
 * - ES256 (ECDSA with SHA-256): P-256, brainpoolP256r1
 * - ES384 (ECDSA with SHA-384): P-384, brainpoolP320r1, brainpoolP384r1
 * - ES512 (ECDSA with SHA-512): P-521, brainpoolP512r1
 * - EdDSA: Ed25519, Ed448
 */
const CURVE_TO_ALG: Record<string, SupportedAlgs> = {
  'P-256': 'ES256',
  'brainpoolP256r1': 'ES256',
  'P-384': 'ES384',
  'brainpoolP320r1': 'ES384',
  'brainpoolP384r1': 'ES384',
  'P-521': 'ES512',
  'brainpoolP512r1': 'ES512',
  'Ed25519': 'EdDSA',
  'Ed448': 'EdDSA',
} as const;

/**
 * Determines the signature algorithm based on the JWK curve parameter.
 * 
 * @param crv - The curve identifier from the JWK
 * @returns The corresponding signature algorithm
 * @throws Error if the curve is not supported
 */
export function getAlgFromCurve(crv: string | undefined): SupportedAlgs {
  if (!crv) {
    throw new Error('Missing curve (crv) parameter in device key');
  }
  const alg = CURVE_TO_ALG[crv as keyof typeof CURVE_TO_ALG];
  if (!alg) {
    throw new Error(`Unsupported curve: ${crv}`);
  }
  return alg;
}

