import * as jose from 'jose';

/**
 * Interface for signing operations that can be implemented by various
 * signing mechanisms (local keys, HSMs, KMS, etc.)
 */
export interface Signer {
  /**
   * Sign data using the configured signing mechanism
   * @param algorithm - The COSE algorithm identifier (e.g., 'ES256', 'ES384', 'ES512')
   * @param data - The data to sign
   * @returns The signature as a Uint8Array
   */
  sign(algorithm: string, data: Uint8Array): Promise<Uint8Array>;

  /**
   * Get the public key information for this signer in JWK format
   * @returns The public key as a JWK
   */
  getPublicKey(): Promise<jose.JWK>;

  /**
   * Get the key ID for this signer
   * @returns The key ID as a string, Uint8Array, or undefined
   */
  getKeyId(): string | Uint8Array | undefined;
}
