import * as jose from 'jose';
import { CryptographyClient, KeyClient, SignatureAlgorithm } from '@azure/keyvault-keys';
import { TokenCredential, DefaultAzureCredential } from '@azure/identity';
import { createHash } from 'crypto';
import { Signer } from '../../../src/mdoc/signing/Signer';
import { SupportedAlgs } from '../../../src/mdoc/model/types';

export interface AzureKeyVaultSignerConfig {
  /**
   * The Azure Key Vault URL (e.g., 'https://my-vault.vault.azure.net')
   */
  keyVaultUrl: string;

  /**
   * The name of the key in Azure Key Vault
   */
  keyName: string;

  /**
   * The algorithm to use for signing (must match the key type in Azure Key Vault)
   */
  algorithm: SupportedAlgs;

  /**
   * Optional key version. If not specified, uses the latest version.
   */
  keyVersion?: string;

  /**
   * Optional Azure credential. If not specified, uses DefaultAzureCredential.
   */
  credential?: TokenCredential;
}

/**
 * Azure Key Vault-based signer that uses Azure Key Vault to perform signing operations.
 * This allows signing with private keys stored in Azure Key Vault without exposing
 * the private key material.
 */
export class AzureKeyVaultSigner implements Signer {
  private cryptoClient: CryptographyClient;
  private keyClient: KeyClient;
  private keyName: string;
  private keyVersion?: string;
  private credential: TokenCredential;
  private keyVaultUrl: string;
  private algorithm: SupportedAlgs;
  private cachedPublicKey?: jose.JWK;

  constructor(config: AzureKeyVaultSignerConfig) {
    // Normalize the key vault URL by removing trailing slash
    this.keyVaultUrl = config.keyVaultUrl.replace(/\/$/, '');
    this.keyName = config.keyName;
    this.keyVersion = config.keyVersion;
    this.algorithm = config.algorithm;
    this.credential = config.credential || new DefaultAzureCredential();

    this.keyClient = new KeyClient(this.keyVaultUrl, this.credential);

    // Initialize the cryptography client
    // If keyVersion is provided, use it; otherwise, use the key name which will use the
    // latest version
    const keyId = this.keyVersion
      ? `${this.keyVaultUrl}/keys/${this.keyName}/${this.keyVersion}`
      : `${this.keyVaultUrl}/keys/${this.keyName}`;

    this.cryptoClient = new CryptographyClient(keyId, this.credential);
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    // Azure Key Vault's sign operation expects a digest, not the raw data
    // So we need to hash the data first
    const digest = this.hashData(this.algorithm, data);

    // Map COSE algorithm to Azure signature algorithm
    const azureAlgorithm = this.mapCOSEtoAzureAlgorithm(this.algorithm);

    // Perform the signing operation in Azure Key Vault
    const signResult = await this.cryptoClient.sign(azureAlgorithm, digest);

    return new Uint8Array(signResult.result);
  }

  async getPublicKey(): Promise<jose.JWK> {
    if (this.cachedPublicKey) {
      return this.cachedPublicKey;
    }

    // Retrieve the key from Azure Key Vault
    const keyVaultKey = await this.keyClient.getKey(this.keyName, { version: this.keyVersion });

    if (!keyVaultKey.key) {
      throw new Error(`Failed to retrieve key ${this.keyName} from Azure Key Vault`);
    }

    // Convert Azure Key Vault key to JWK format
    const jwk = this.azureKeyToJWK(keyVaultKey.key);

    this.cachedPublicKey = jwk;
    return jwk;
  }

  getKeyId(): string {
    return this.keyName;
  }

  getAlgorithm(): SupportedAlgs {
    return this.algorithm;
  }

  /**
   * Hash the data according to the algorithm
   * @param algorithm - COSE algorithm identifier
   * @param data - Data to hash
   * @returns The digest
   */
  private hashData(algorithm: string, data: Uint8Array): Uint8Array {
    const hashAlgorithm = this.getHashAlgorithm(algorithm);
    const hash = createHash(hashAlgorithm);
    hash.update(data);
    return new Uint8Array(hash.digest());
  }

  /**
   * Get the hash algorithm for a COSE algorithm
   * @param coseAlg - COSE algorithm identifier
   * @returns Hash algorithm name for Node.js crypto
   */
  private getHashAlgorithm(coseAlg: string): string {
    const hashMap: Record<string, string> = {
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

    const hash = hashMap[coseAlg];
    if (!hash) {
      throw new Error(`Unsupported COSE algorithm for hashing: ${coseAlg}`);
    }

    return hash;
  }

  /**
   * Map COSE algorithm to Azure Key Vault signature algorithm
   *
   * Supported algorithms:
   * - ES256 (ECDSA with P-256 curve and SHA-256)
   * - ES384 (ECDSA with P-384 curve and SHA-384)
   * - ES512 (ECDSA with P-521 curve and SHA-512)
   * - RS256, RS384, RS512, PS256, PS384, PS512 (RSA algorithms)
   *
   * NOT supported:
   * - EdDSA (Ed25519) - Azure Key Vault HSM does not support Ed25519 keys
   *
   * @param coseAlg - COSE algorithm identifier (e.g., 'ES256', 'ES384', 'ES512')
   * @returns Azure SignatureAlgorithm
   * @throws Error if algorithm is not supported
   */
  private mapCOSEtoAzureAlgorithm(coseAlg: string): SignatureAlgorithm {
    // EdDSA is explicitly not supported by Azure Key Vault HSM
    if (coseAlg === 'EdDSA') {
      throw new Error(
        'EdDSA (Ed25519) is not supported by Azure Key Vault HSM. ' +
        'Supported elliptic curve algorithms: ES256, ES384, ES512. ' +
        'Supported RSA algorithms: RS256, RS384, RS512, PS256, PS384, PS512.',
      );
    }

    const algorithmMap: Record<string, SignatureAlgorithm> = {
      ES256: 'ES256',
      ES384: 'ES384',
      ES512: 'ES512',
      RS256: 'RS256',
      RS384: 'RS384',
      RS512: 'RS512',
      PS256: 'PS256',
      PS384: 'PS384',
      PS512: 'PS512',
    };

    const azureAlg = algorithmMap[coseAlg];
    if (!azureAlg) {
      throw new Error(`Unsupported COSE algorithm for Azure Key Vault: ${coseAlg}`);
    }

    return azureAlg;
  }

  /**
   * Convert Azure Key Vault key to JWK format
   * @param azureKey - Key from Azure Key Vault
   * @returns JWK representation of the public key
   */
  private azureKeyToJWK(azureKey: any): jose.JWK {
    // Azure Key Vault returns keys in JWK format already
    // We just need to extract the public key components
    const jwk: jose.JWK = {
      kty: azureKey.kty.replace('-HSM', ''), // Normalize EC-HSM to EC, RSA-HSM to RSA
      kid: azureKey.kid,
    };

    if (azureKey.kty === 'EC' || azureKey.kty === 'EC-HSM') {
      jwk.crv = azureKey.crv;
      jwk.x = azureKey.x;
      jwk.y = azureKey.y;
    } else if (azureKey.kty === 'RSA' || azureKey.kty === 'RSA-HSM') {
      jwk.n = azureKey.n;
      jwk.e = azureKey.e;
    } else {
      throw new Error(`Unsupported key type: ${azureKey.kty}`);
    }

    return jwk;
  }
}
