import { Tagged } from 'cbor';
import crypto from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import { Crypto as WebCrypto } from '@peculiar/webcrypto';
import * as pkijs from 'pkijs';
import { cborEncode, cborDecode } from '../cose/cbor';
import { RawDeviceNameSpaces } from './types.d';

const webcrypto = new WebCrypto();
pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto', crypto: webcrypto, subtle: webcrypto.subtle }));

export const calculateDigest = (
  alg: string,
  elementValueToEvaluate: Tagged,
) => crypto
  .createHash(alg)
  .update(cborEncode(elementValueToEvaluate))
  .digest();

export const calculateEphemeralMacKey = (
  deviceKey: Buffer,
  ephemeralPrivateKey: Buffer,
  sessionTranscriptBytes: Buffer,
): Buffer => {
  const ka = crypto.createECDH('prime256v1');
  ka.setPrivateKey(ephemeralPrivateKey);
  const sharedSecret = ka.computeSecret(deviceKey);
  const info = Buffer.from('454d61634b6579', 'hex'); // 'EMacKey' in hex
  const salt = crypto
    .createHash('sha256')
    .update(sessionTranscriptBytes)
    .digest();

  const prk = crypto.createHmac('sha256', salt).update(sharedSecret).digest();
  const result = Buffer.alloc(32);
  let ctr = 1;
  let pos = 0;
  const mac = crypto.createHmac('sha256', prk);
  let digest = '';

  // eslint-disable-next-line no-constant-condition
  while (true) {
    mac.write(digest, 'binary');
    mac.write(info, 'binary');
    mac.write(String.fromCharCode(ctr), 'binary');
    digest = mac.digest('binary');
    const digestLength = Buffer.byteLength(digest, 'binary');
    if (pos + digestLength < 32) {
      result.write(digest, pos, digestLength, 'binary');
      pos += digestLength;
      ctr += 1;
    } else {
      result.write(digest, pos, 32 - pos, 'binary');
      break;
    }
  }

  return result;
};

export const calculateDeviceAutenticationBytes = (
  sessionTranscriptBytes: Buffer,
  docType: string,
  nameSpaces: RawDeviceNameSpaces,
): Buffer => cborEncode(
  new Tagged(
    24,
    cborEncode([
      'DeviceAuthentication',
      cborDecode(
        (cborDecode(sessionTranscriptBytes, { skipExtraTags: true }) as Tagged).value,
        { skipExtraTags: true },
      ),
      docType,
      nameSpaces,
    ]),
  ),
);

const pemToCert = (cert: string): string => {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return '';
};

export const parseAndValidateCertificateChain = async (rawCertChain: string[], caCerts: string[]): Promise<X509Certificate> => {
  const chainEngine = new pkijs.CertificateChainValidationEngine({
    certs: rawCertChain.map((c) => pkijs.Certificate.fromBER(Buffer.from(c, 'base64'))),
    trustedCerts: caCerts.map((c) => pkijs.Certificate.fromBER(Buffer.from(pemToCert(c), 'base64'))),
  });

  const chain = await chainEngine.verify();
  // if (!chain.result) {
  //   throw new Error(`Invalid certificate chain: ${chain.resultMessage}`);
  // }

  return new X509Certificate(rawCertChain[0]);
};
