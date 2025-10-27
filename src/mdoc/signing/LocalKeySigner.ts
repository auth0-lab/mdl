import * as jose from 'jose';
import { createSign } from 'crypto';
import { Signer } from './Signer';

/**
 * Local key-based signer that uses JWK for signing operations.
 * This provides backward compatibility with the existing signing mechanism.
 */
export class LocalKeySigner implements Signer {
  private jwk: jose.JWK;

  constructor(jwk: jose.JWK) {
    this.jwk = jwk;
  }

  async sign(algorithm: string, data: Uint8Array): Promise<Uint8Array> {
    // Import the JWK as a KeyLike object
    const key = await jose.importJWK(this.jwk);

    // Map COSE algorithm to Node.js digest algorithm
    const digestAlgorithm = this.mapCOSEAlgorithmToNodeDigest(algorithm);

    // Use Node.js crypto to sign
    const signer = createSign(digestAlgorithm);
    signer.update(data);
    signer.end();

    // KeyLike from jose.importJWK is compatible with Node.js crypto
    const signature = signer.sign(key as any);
    return new Uint8Array(signature);
  }

  async getPublicKey(): Promise<jose.JWK> {
    // Remove the private key component to get the public key
    const { d, ...publicKey } = this.jwk;
    return publicKey;
  }

  getKeyId(): string | Uint8Array | undefined {
    return this.jwk.kid;
  }

  /**
   * Map COSE algorithm names to Node.js digest algorithm names
   * @param coseAlg - COSE algorithm identifier (e.g., 'ES256', 'ES384', 'ES512')
   * @returns Node.js digest algorithm name
   */
  private mapCOSEAlgorithmToNodeDigest(coseAlg: string): string {
    const algorithmMap: Record<string, string> = {
      ES256: 'sha256',
      ES384: 'sha384',
      ES512: 'sha512',
      RS256: 'RSA-SHA256',
      RS384: 'RSA-SHA384',
      RS512: 'RSA-SHA512',
      PS256: 'RSA-SHA256',
      PS384: 'RSA-SHA384',
      PS512: 'RSA-SHA512',
    };

    const nodeAlg = algorithmMap[coseAlg];
    if (!nodeAlg) {
      throw new Error(`Unsupported COSE algorithm: ${coseAlg}`);
    }

    return nodeAlg;
  }
}
