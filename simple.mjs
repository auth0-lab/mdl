import crypto from 'crypto';
import { p256 } from '@noble/curves/p256';
import { toBufferBE } from 'bigint-buffer';
import { secp256k1 } from '@noble/curves/secp256k1';

// const { privateKey } = await crypto.subtle.generateKey(
//   { name: 'ECDH', namedCurve: 'P-256' },
//   true,
//   ['deriveBits'],
// );

// const privKey = await crypto.subtle.exportKey('jwk', privateKey);

// console.dir(privKey);

// const { d } = privKey;

// // calculate x and y from d
// // const { x, y } = @nobleCurves.getCurveByName('p256').G.mul(d);

// const pp = p256.ProjectivePoint.fromPrivateKey(Buffer.from(d, 'base64url'));

// console.log(toBufferBE(pp.x, 32).toString('base64url'));
// console.log(toBufferBE(pp.y, 32).toString('base64url'));

// const jwk = {
//   kty: 'EC',
//   crv: 'P-256',
//   x: toBufferBE(pp.x, 32).toString('base64url'),
//   y: toBufferBE(pp.y, 32).toString('base64url'),
//   d,
// };

// const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);

// console.dir(key);


/// another

const deviceKey = Buffer.from('0496313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a1fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6', 'hex');
const ephemeralKey = Buffer.from('de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c', 'hex');
// const sesionTranscriptBytes = Buffer.from('d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414', 'hex');
// const sharedSecret = Buffer.from(
//   '78d98a86fbbb82895874bfafcc161ba69f9b77662172c74b3b0d4643276cf991',
// '78d98a86fbbb82895874bfafcc161ba69f9b77662172c74b3b0d4643276cf991'
//  '78d98a86fbbb82895874bfafcc161ba69f9b77662172c74b3b0d4643276cf991'
//   'hex'
// );

const shared = p256.getSharedSecret(ephemeralKey, deviceKey, true);

console.log(Buffer.from(shared.slice(1)).toString('hex'));

// const info = Buffer.from('454d61634b6579', 'hex'); // 'EMacKey' in hex
// const salt = Buffer.from(
//   'f823ac566e22b2106c9b7c02fadc7482e559a1de8a809b56c828779e6d67570e',
//   'hex',
// );

// c
