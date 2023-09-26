import { concat } from '../buffer_utils';

const coseKeyMapToBuffer = (
  deviceKeyCoseKey: Map<number, Uint8Array | number>,
): Uint8Array => {
  const kty = deviceKeyCoseKey.get(1);
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
  }

  const crv = deviceKeyCoseKey.get(-1);
  if (crv !== 1) {
    throw new Error(`Expected COSE Key EC2 Curve: P-256 (1), got: ${crv}`);
  }

  const newLocal = Uint8Array.from([0x04]);
  return concat(
    newLocal,
    deviceKeyCoseKey.get(-2) as Uint8Array,
    deviceKeyCoseKey.get(-3) as Uint8Array,
  );
};

export default coseKeyMapToBuffer;
