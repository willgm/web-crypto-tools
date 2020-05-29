/**
 * Import Key Algorithms at Web Crypto API
 */
export type ImportAlgorithm =
  | string
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | DhImportKeyParams
  | AesKeyAlgorithm;

/**
 * Import Key Web Crypto Algorithms
 */
export type OriginalKeyFormat = 'raw' | 'pkcs8' | 'spki' | 'jwk';

/**
 * Derive Key Algorithms at at Web Crypto API
 */
export type DeriveAlgorithm =
  | string
  | EcdhKeyDeriveParams
  | DhKeyDeriveParams
  | ConcatParams
  | HkdfCtrParams
  | Pbkdf2Params;

/**
 * Derive Algorithms Params for Web Crypto API
 */
export type DerivedAlgorithmFor =
  | string
  | AesDerivedKeyParams
  | HmacImportParams
  | ConcatParams
  | HkdfCtrParams
  | Pbkdf2Params;

/**
 * Params for Encrypt / Decrypt Algorithms at Web Crypto API
 */
export type CryptoAlgorithm =
  | string
  | RsaOaepParams
  | AesCtrParams
  | AesCbcParams
  | AesCmacParams
  | AesGcmParams
  | AesCfbParams;

/**
 * TypedArray used in Web Crypto API Algorithms
 */
export type TypedArray =
  | Int8Array
  | Int16Array
  | Int32Array
  | Uint8Array
  | Uint16Array
  | Uint32Array
  | Uint8ClampedArray
  | Float32Array
  | Float64Array
  | DataView
  | ArrayBuffer;

/**
 * Possible uses of Crypto Keys
 */
export type CryptoKeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'sign'
  | 'verify'
  | 'unwrapKey';

/**
 * Default number of iterations used with PBKDF2 algorithm
 */
export const PBKDF2_ITERATIONS_DEFAULT: number = 50000;

/**
 * Creates a base Crypto Key from the original raw key, by default this base key
 * should just be used to protect the original key to be discovery,
 * and should not be used directly to any encrypt / decrypt algorithm.
 * The generated base crypto key should be used just to derive new ones,
 * that then will be used to encrypt / decrypt algorithms.
 *
 * @param rawKey The original key to start the encrypt process.
 * @param algorithm The algorithm used to import the key.
 * @param keyUsages The uses for the generated Crypto Key.
 * @param format Input format for the raw key.
 * @returns A promise with the base Crypto Key.
 */
export function generateBaseCryptoKey(
  rawKey: string | TypedArray | JsonWebKey,
  algorithm: ImportAlgorithm = 'PBKDF2',
  keyUsages: KeyUsage[] = ['deriveKey'],
  format: OriginalKeyFormat = 'raw',
): Promise<CryptoKey> {
  const isJwkKey = !isTypedArray(rawKey) && typeof rawKey === 'object';
  return Promise.resolve(
    crypto.subtle.importKey(
      isJwkKey ? 'jwk' : format,
      typeof rawKey === 'string' ? encode(rawKey) : rawKey,
      algorithm,
      false, // the original value will not be extractable
      keyUsages,
    ),
  );
}

/**
 * Derives a base Crypto Key to new one that can be used in encrypt / decrypt algorithms
 * or any other possible uses in `CryptoKeyUsage`.
 *
 * @param cryptoBaseKey The base Crypto Key to be derive.
 * @param salt The salt value to be used with the default `PBKDF2` derive algorithm.
 * @param iterations The number of iterations to be used with the default `PBKDF2` derive algorithm. Default value: `PBKDF2_ITERATIONS_DEFAULT`.
 * @param keyUsages The new uses of the new derive Crypto Key. Default value: `['encrypt', 'decrypt']`.
 * @returns A promise with the derived Crypto Key for other uses.
 */
export function deriveCryptKey(
  cryptoBaseKey: CryptoKey,
  salt: TypedArray,
  iterations?: number,
  keyUsages?: CryptoKeyUsage[],
): Promise<CryptoKey>;

/**
 * Derives a base Crypto Key to new one that can be used in encrypt / decrypt algorithms
 * or any other possible uses in `CryptoKeyUsage`.
 *
 * @param cryptoBaseKey The base Crypto Key to be derive.
 * @param salt The salt value to be used with the default `PBKDF2` derive algorithm.
 * @param algorithmFor The algorithm where the derived Crypto Key will be used. Default value: `{ name: 'AES-GCM', length: 256 }`.
 * @param keyUsages The new uses of the new derive Crypto Key. Default value: `['encrypt', 'decrypt']`.
 * @returns A promise with the derived Crypto Key for other uses.
 */
export function deriveCryptKey(
  cryptoBaseKey: CryptoKey,
  salt: TypedArray,
  algorithmFor?: DerivedAlgorithmFor,
  keyUsages?: CryptoKeyUsage[],
): Promise<CryptoKey>;

/**
 * Derives a base Crypto Key to new one that can be used in encrypt / decrypt algorithms
 * or any other possible uses in `CryptoKeyUsage`.
 *
 * @param cryptoBaseKey The base Crypto Key to be derive.
 * @param deriveAlgorithm The algorithm to be used when deriving the Crypto Key.
 * @param algorithmFor The algorithm where the derived Crypto Key will be used. Default value: `{ name: 'AES-GCM', length: 256 }`.
 * @param keyUsages The new uses of the new derive Crypto Key. Default value: `['encrypt', 'decrypt']`.
 * @returns A promise with the derived Crypto Key for other uses.
 */
export function deriveCryptKey(
  cryptoBaseKey: CryptoKey,
  deriveAlgorithm: DeriveAlgorithm,
  algorithmFor?: DerivedAlgorithmFor,
  keyUsages?: CryptoKeyUsage[],
): Promise<CryptoKey>;

export function deriveCryptKey(
  cryptoBaseKey: CryptoKey,
  deriveAlgorithmOrSalt: DeriveAlgorithm | TypedArray,
  algorithmForOrIterations: DerivedAlgorithmFor | number = PBKDF2_ITERATIONS_DEFAULT,
  keyUsages: CryptoKeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> {
  const deriveAlgorithm = isTypedArray(deriveAlgorithmOrSalt)
    ? ({
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: deriveAlgorithmOrSalt,
        iterations:
          typeof algorithmForOrIterations === 'number'
            ? algorithmForOrIterations
            : PBKDF2_ITERATIONS_DEFAULT,
      } as Pbkdf2Params)
    : deriveAlgorithmOrSalt;

  // The derived key will be used to encrypt with AES by default.
  const algorithmFor =
    typeof algorithmForOrIterations === 'number'
      ? ({ name: 'AES-GCM', length: 256 } as AesDerivedKeyParams)
      : algorithmForOrIterations;

  return Promise.resolve(
    crypto.subtle.deriveKey(
      deriveAlgorithm,
      cryptoBaseKey,
      algorithmFor,
      false, // the original key will not be extractable
      keyUsages,
    ),
  );
}

/**
 * Type Guard to Typed Array.
 *
 * @param data Any data to be checked.
 * @returns Verify if the given data is a Typed Array.
 */
export function isTypedArray(data: unknown): data is TypedArray {
  return ArrayBuffer.isView(data) || data instanceof ArrayBuffer;
}

/**
 * Encrypt a value with the given Crypto Key and Algorithm
 *
 * @param data Value to be encrypted.
 * @param cryptoKey The Crypto Key to be used in encryption.
 * @param algorithm The algorithm to be used in encryption. Default to `AES-GCM`.
 * @returns A promise with the encrypted value and the used nonce, if used with the encryption algorithm.
 */
export function encryptValue(
  data: string | TypedArray,
  cryptoKey: CryptoKey,
  algorithm: CryptoAlgorithm = { name: 'AES-GCM', iv: generateNonce() } as AesGcmParams,
): Promise<[ArrayBuffer, TypedArray | null]> {
  return Promise.resolve(
    crypto.subtle.encrypt(algorithm, cryptoKey, encode(data)),
  ).then(cryptoValue => [cryptoValue, (algorithm as AesGcmParams).iv || null]);
}

/**
 * Decrypt a value with the given Crypto Key and Algorithm
 *
 * @param data Value to be encrypted.
 * @param cryptoKey The Crypto Key used in encryption.
 * @param nonceOrAlgorithm The nonce used for AES encryption or the custom algorithm.
 * @returns A promise with the decrypt value
 */
export function decryptValue(
  data: TypedArray,
  cryptoKey: CryptoKey,
  nonceOrAlgorithm: TypedArray | CryptoAlgorithm,
): Promise<ArrayBuffer> {
  const algorithm = isTypedArray(nonceOrAlgorithm)
    ? ({ name: 'AES-GCM', iv: nonceOrAlgorithm } as AesGcmParams)
    : nonceOrAlgorithm;
  return Promise.resolve(crypto.subtle.decrypt(algorithm, cryptoKey, data));
}

/**
 * Generates random value to be used as nonce with encryption algorithms.
 *
 * @param byteSize The byte size of the generated random value.
 * @returns The random value.
 */
export function generateNonce(byteSize = 16): Uint8Array {
  // We should generate at least 16 bytes
  // to allow for 2^128 possible variations.
  return generateRandomValues(byteSize);
}

/**
 * Generates random value to be used as salt with encryption algorithms.
 *
 * @param byteSize The byte size of the generated random value.
 * @returns The random value.
 */
export function generateSalt(byteSize = 8): Uint8Array {
  // We should generate at least 8 bytes
  // to allow for 2^64 possible variations.
  return generateRandomValues(byteSize);
}

/**
 * Generates random value as a typed array of `Uint8Array`.
 *
 * @param byteSize The byte size of the generated random value.
 * @returns The random value.
 */
export function generateRandomValues(byteSize = 8): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(byteSize));
}

/**
 * Encode a string value to a Typed Array as `Uint8Array`.
 * If the given value is already a Typed Array, then the value will be returned without any transformation.
 *
 * @param data Value to be encoded.
 * @returns The transformed given value as a Typed Array.
 */
export function encode(data: string | TypedArray): TypedArray {
  return isTypedArray(data) ? data : new TextEncoder().encode(data);
}

/**
 * Decode a ArrayBuffer value to a string.
 * If the given value is already a string, then the value will be returned without any transformation.
 *
 * @param data Value to be decoded.
 * @returns The transformed given value as a string.
 */
export function decode(data: string | TypedArray): string {
  return typeof data === 'string' ? data : new TextDecoder('utf-8').decode(data);
}

/**
 * Generates a hash value for the given value.
 *
 * @param data Seed value to generate a hash.
 * @param algorithm The algorithm to be used when generating the hash.
 * @returns A promise containing the hash value.
 */
export function generateHash(
  data: string | TypedArray,
  algorithm: string | Algorithm = 'SHA-256',
): Promise<ArrayBuffer> {
  return Promise.resolve(crypto.subtle.digest(algorithm, encode(data)));
}
