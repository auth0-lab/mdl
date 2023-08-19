export const parseCoseKeyMapToBuffer = (
  deviceKeyCoseKey: Map<number, Buffer | number>,
): Buffer => {
  const kty = deviceKeyCoseKey.get(1);
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
  }

  const crv = deviceKeyCoseKey.get(-1);
  if (crv !== 1) {
    throw new Error(`Expected COSE Key EC2 Curve: P-256 (1), got: ${crv}`);
  }

  return Buffer.concat([
    Buffer.from([0x04]),
    deviceKeyCoseKey.get(-2) as Buffer,
    deviceKeyCoseKey.get(-3) as Buffer,
  ]);
};

export const parseCoseKeyMapToJwk = (
  deviceKeyCoseKey: Map<number, Buffer | number>,
): { x: string, y: string } => {
  const kty = deviceKeyCoseKey.get(1);
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
  }

  const crv = deviceKeyCoseKey.get(-1);
  if (crv !== 1) {
    throw new Error(`Expected COSE Key EC2 Curve: P-256 (1), got: ${crv}`);
  }

  return {
    x: (deviceKeyCoseKey.get(-2) as Buffer).toString('base64url'),
    y: (deviceKeyCoseKey.get(-3) as Buffer).toString('base64url'),
  };
};
