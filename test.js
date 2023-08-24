// const crypto = require('crypto');
const   { Crypto } = require('@peculiar/webcrypto');
// import { Crypto } from '@peculiar/webcrypto';

const jwk = {
  'alg': 'ES256',
  'kty': 'EC',
  'crv': 'P-256',
  'x': 'w7-oner9UxkL92iXDUTo5193cVjmP56jxrYMEW1_W_g',
  'y': 'vYAd0xtTrS53zUarPb0gLQgZqBsKPwzh5goLifzFQr4'
};

const signature = Buffer.from(
  '_PBYUcRVunb3daymqOpMuK1Kn9y2TDuzM_hGWB491y9ALzIyWOmKbqgmyD0526XqgBuE4hp-7bHdCeINT45klw==',
  'base64url'
);

(async () => {
  const crypto = new Crypto( );
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

  const r = await crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    key,
    signature,
    Buffer.from('test', 'utf8')
  );

  console.log(r);

})();;
