import { Tagged } from 'cbor';
import crypto from 'node:crypto';
import { cborEncode, cborDecode } from '../cose/cbor';
import { RawDeviceNameSpaces } from './types.d';

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
