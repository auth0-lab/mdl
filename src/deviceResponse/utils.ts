import { subtle } from 'uncrypto';
import { X509Certificate } from '@peculiar/x509';
import { Crypto as WebCrypto } from '@peculiar/webcrypto';
import * as pkijs from 'pkijs';
import { p256 } from '@noble/curves/p256';
import { cborEncode, cborDecode } from '../cose/cbor';
import { NameSpaces } from './types';
import { DataItem } from '../cose/DataItem';

const webcrypto = new WebCrypto();

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

export const calculateEphemeralMacKey = async (
  deviceKey: ArrayBuffer,
  ephemeralPrivateKey: ArrayBuffer,
  sessionTranscriptBytes: ArrayBuffer,
): Promise<ArrayBuffer> => {
  const sharedSecret = p256.getSharedSecret(
    Buffer.from(ephemeralPrivateKey).toString('hex'),
    Buffer.from(deviceKey).toString('hex'),
    true,
  ).slice(1);

  const info = Buffer.from('454d61634b6579', 'hex'); // 'EMacKey' in hex
  const salt = await subtle.digest('SHA-256', sessionTranscriptBytes);
  const prk = await hmacSHA256(salt, sharedSecret);

  const result = Buffer.alloc(32);
  let ctr = 1;
  let pos = 0;
  let digest = Buffer.alloc(0);

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const data = Buffer.concat([
      digest,
      info,
      Buffer.from(String.fromCharCode(ctr)),
    ]);
    // digest = Buffer.from(await subtle.sign('HMAC', prkHMACKey, data));
    digest = Buffer.from(await hmacSHA256(prk, data));
    const digestLength = digest.byteLength;
    if (pos + digestLength < 32) {
      result.set(digest, pos);
      pos += digestLength;
      ctr += 1;
    } else {
      result.set(digest.subarray(0, 32 - pos), pos);
      break;
    }
  }

  return result;
};

export const calculateDeviceAutenticationBytes = (
  sessionTranscriptBytes: Buffer,
  docType: string,
  nameSpaces: NameSpaces,
): Buffer => {
  const { data: decodedSessionTranscript } = cborDecode(sessionTranscriptBytes) as DataItem;

  const encode = DataItem.fromData([
    'DeviceAuthentication',
    decodedSessionTranscript,
    docType,
    nameSpaces,
  ]);

  const result = cborEncode(encode);

  return result;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const pemToCert = (cert: string): string => {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return '';
};

export const parseAndValidateCertificateChain = async (rawCertChain: string[], caCerts: string[]): Promise<X509Certificate> => {
  // const chainEngine = new pkijs.CertificateChainValidationEngine({
  //   certs: rawCertChain.map((c) => pkijs.Certificate.fromBER(Buffer.from(c, 'base64'))),
  //   trustedCerts: caCerts.map((c) => pkijs.Certificate.fromBER(Buffer.from(pemToCert(c), 'base64'))),
  // });

  // const chain = await chainEngine.verify();
  // if (!chain.result) {
  //   throw new Error(`Invalid certificate chain: ${chain.resultMessage}`);
  // }

  return new X509Certificate(rawCertChain[0]);
};
