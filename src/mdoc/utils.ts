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
  privateKey: Uint8Array,
  publicKey: Uint8Array,
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
