import { X509Certificate } from '@peculiar/x509';
import crypto from 'node:crypto';
import { Tagged } from 'cbor';
import ChainValidator from '../validate/ChainValidator';
import KnownAlgorithmValidator from '../validate/cose/KnownAlgorithmValidator';
import CoseSign1 from '../cose/CoseSign1';
import CoseMac0 from '../cose/CoseMac0';
import { extractX5Chain } from '../cose/header/headers';
import HasX5chainValidator from '../validate/cose/HasX5chainValidator';
import { CoseMacAlgorithm, CoseSignAlgorithm } from '../cose/algorithms';
import { cborDecode, cborEncode } from '../cose/cbor';
import { DeviceAuth, RawDeviceNameSpaces, ValidityInfo } from './deviceResponse';
import coseKeyMapToBuffer from '../cose/coseKey';

/*
* Confirm that the mdoc data is issued by the issuing authority.
*
*/
export const verifyIssuerSignature = async (msg: CoseSign1):
  Promise<{ validityInfo: ValidityInfo }> => {
  const validator = new ChainValidator([
    new KnownAlgorithmValidator([CoseSignAlgorithm.ECDS_256]),
    new HasX5chainValidator(),
  ]);

  const validationResult = validator.validate(msg);
  if (!validationResult.isValid()) {
    throw new Error(`issuerAuth is not valid: ${validationResult.getMessage()}`);
  }

  // Parse issuer certificate
  // TODO: validate cert root authority
  const rawIssuerCert = extractX5Chain(msg.getUnprotectedHeaders());
  const issuerCert = new X509Certificate(rawIssuerCert);
  const verificationResult = await msg.verify(issuerCert.publicKey.rawData);
  if (!verificationResult) {
    throw new Error('issuerAuth signature is tempered');
  }

  // Validity
  const { validityInfo } = msg.getDecodedPayload();
  const now = new Date();
  if (validityInfo.signed < issuerCert.notBefore && validityInfo.signed > issuerCert.notAfter) {
    throw new Error(`The MSO signed date (${validityInfo.signed}) is not within the validity period of the certificate (${issuerCert.notBefore} to ${issuerCert.notAfter})`);
  }

  if (now < validityInfo.validFrom) {
    throw new Error(`The MSO is not valid until ${validityInfo.validFrom}`);
  }

  if (validityInfo.validUntil < now) {
    // TODO throw new Error(`The MSO was expired at ${validityInfo.validUntil}`);
  }

  // TODO
  // If the mDL reader retrieved the “issuing_country” data element, it shall verify that the value
  // of that element matches the countryName element in the subject field within the DS certificate.
  // if the mDL reader retrieved the “issuing_jurisdiction” data element, it shall verify that the
  // value of that element matches the stateOrProvinceName element in the subject field within the
  // DS certificate.
  // This is only required if the stateOrProvinceName element is present in the DS cert.
  return { validityInfo };
};

const calculateEphemeralMacKey = (
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

const calculateDeviceAutenticationBytes = (
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

/*
* Prevent cloning of the mdoc and mitigate man in the middle attacks.
*
*/
export const verifyDeviceSignature = async (
  deviceAuth: DeviceAuth,
  options: {
    deviceKeyCoseKey: Map<number, Buffer | number>;
    ephemeralPrivateKey: Buffer;
    sessionTranscriptBytes: Buffer;
    docType: string;
    nameSpaces: RawDeviceNameSpaces;
  },
) => {
  const deviceKey = coseKeyMapToBuffer(options.deviceKeyCoseKey);
  const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
    options.sessionTranscriptBytes,
    options.docType,
    options.nameSpaces,
  );

  if (deviceAuth.deviceSignature) {
    // ECDSA/EdDSA authentication
    // TODO: this case is not tested yet
    const validator = new ChainValidator([
      new KnownAlgorithmValidator([CoseSignAlgorithm.ECDS_256]),
    ]);
    const validationResult = validator.validate(deviceAuth.deviceSignature);
    if (!validationResult.isValid()) {
      throw new Error(`deviceAuth.deviceSignature is not valid: ${validationResult.getMessage()}`);
    }

    const verificationResult = await deviceAuth.deviceSignature.verify(
      deviceKey,
      deviceAuthenticationBytes,
    );
    if (!verificationResult) {
      throw new Error('deviceAuth.deviceSignature is tempered');
    }
    return;
  }

  // MAC authentication
  const { deviceMac } = deviceAuth;
  if (!deviceMac) {
    throw new Error('deviceAuth element does not contain a deviceSignature or deviceMac element');
  }

  const validator = new ChainValidator([
    new KnownAlgorithmValidator([CoseMacAlgorithm.HMAC_256_256]),
  ]);
  const validationResult = validator.validate(deviceMac);
  if (!validationResult.isValid()) {
    throw new Error(`deviceAuth.deviceMac is not valid: ${validationResult.getMessage()}`);
  }

  const ephemeralMacKey = calculateEphemeralMacKey(
    deviceKey,
    options.ephemeralPrivateKey,
    options.sessionTranscriptBytes,
  );
  const expectedMac = await CoseMac0.generate(
    ephemeralMacKey,
    Buffer.alloc(0),
    deviceAuthenticationBytes,
  );

  if (expectedMac.getTag().compare(deviceMac.getTag()) !== 0) {
    throw new Error('Device MAC mismatch');
  }
};
