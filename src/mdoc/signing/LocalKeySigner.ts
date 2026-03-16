import * as jose from 'jose';
import { sign as cryptoSign } from 'crypto';
import { Signer } from './Signer';
import { SupportedAlgs } from '../model/types';

/**
 * Local key-based signer that uses JWK for signing operations.
 * This provides backward compatibility with the existing signing mechanism.
 */
export class LocalKeySigner implements Signer {
  private jwk: jose.JWK;
  private algorithm: SupportedAlgs;

  constructor(jwk: jose.JWK, algorithm: SupportedAlgs) {
    this.jwk = jwk;
    this.algorithm = algorithm;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    // Import the JWK as a KeyObject
    const key = await jose.importJWK(this.jwk);

    // Map COSE algorithm to Node.js digest algorithm
    const digestAlgorithm = this.mapCOSEAlgorithmToDigest(this.algorithm);

    // Use Node.js crypto.sign() one-shot API
    // This API will hash the data once with the specified digest algorithm
    // and then sign the hash, which is what COSE expects
    //
    // IMPORTANT: COSE uses IEEE P1363 format (raw R||S concatenation) for ECDSA signatures,
    // not DER encoding. We must specify dsaEncoding: 'ieee-p1363' for EC algorithms.
    const signature = cryptoSign(digestAlgorithm, data, {
      key: key as any,
      dsaEncoding: 'ieee-p1363',
    });
    return new Uint8Array(signature);
  }

  getKeyId(): string | Uint8Array | undefined {
    return this.jwk.kid;
  }

  getAlgorithm(): SupportedAlgs {
    return this.algorithm;
  }

  /**
   * Map COSE algorithm names to Node.js digest algorithm names
   * @param coseAlg - COSE algorithm identifier (e.g., 'ES256', 'ES384', 'ES512')
   * @returns Node.js digest algorithm name
   */
  private mapCOSEAlgorithmToDigest(coseAlg: string): string {
    const algorithmMap: Record<string, string> = {
      ES256: 'sha256',
      ES384: 'sha384',
      ES512: 'sha512',
      RS256: 'sha256',
      RS384: 'sha384',
      RS512: 'sha512',
      PS256: 'sha256',
      PS384: 'sha384',
      PS512: 'sha512',
    };

    const nodeAlg = algorithmMap[coseAlg];
    if (!nodeAlg) {
      throw new Error(`Unsupported COSE algorithm: ${coseAlg}`);
    }

    return nodeAlg;
  }
}
