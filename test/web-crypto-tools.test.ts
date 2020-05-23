import {
  decode,
  decryptValue,
  deriveCryptKey,
  encode,
  encryptValue,
  generateBaseCryptoKey,
  generateHash,
  generateNonce,
  generateRandomValues,
  generateSalt,
  isTypedArray,
} from '../src/web-crypto-tools';

describe('Web Crypto Tools', () => {
  describe('Base Key Creation', () => {
    it('should not be extractable extractable', async () => {
      const subject = await generateBaseCryptoKey('any raw key');
      expect(subject.extractable).toBeFalse();
    });

    it('should accept typed arrays as key data', async () => {
      const subject = await generateBaseCryptoKey(new Uint8Array(8));
      expect(subject.extractable).toBeFalse();
    });

    it('should use PBKDF2 algorithm by default for the base', async () => {
      const subject = await generateBaseCryptoKey('any raw key');
      expect(subject.algorithm).toEqual({ name: 'PBKDF2' });
    });

    it('should be used just for derive a new key by default', async () => {
      const subject = await generateBaseCryptoKey('any raw key');
      expect(subject.usages).toEqual(['deriveKey']);
    });

    it('should work with other algorithms and usages', async () => {
      const subject = await generateBaseCryptoKey(
        generateRandomValues(16),
        'AES-GCM',
        ['encrypt', 'decrypt'],
        'raw',
      );
      expect(subject.algorithm).toEqual({ name: 'AES-GCM', length: 128 } as any);
    });
  });

  describe('Key Derivation', () => {
    it('should be able do derive a new key from a base one', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt());
      expect(subject).toBeDefined();
    });

    it('should be able do derive a new key with custom interaction number', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt(), 100);
      expect(subject.algorithm).toBeDefined();
    });

    it('should not be extractable extractable', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt());
      expect(subject.extractable).toBeFalse();
    });

    it('should be used for encrypt and decrypt by default', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt());
      expect(subject.usages).toEqual(['encrypt', 'decrypt']);
    });

    it('should be able to config the key usage', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt(), undefined, ['encrypt']);
      expect(subject.usages).toEqual(['encrypt']);
    });

    it('should use AES-GCM algorithm with length of 256 by default', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt());
      expect(subject.algorithm).toEqual({ name: 'AES-GCM', length: 256 } as any);
    });

    it('should be able to use other derive algorithm', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, {
        name: 'PBKDF2',
        salt: generateSalt(),
        iterations: 100,
        hash: 'SHA-1',
      });
      expect(subject).toBeDefined();
    });

    it('should be able to use other target encryption algorithm', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const subject = await deriveCryptKey(baseKey, generateSalt(), {
        name: 'AES-CBC',
        length: 256,
      });
      expect(subject.algorithm).toEqual({ name: 'AES-CBC', length: 256 } as any);
    });
  });

  describe('Type Guard to Typed Array', () => {
    it('should return true when testing against any Int Array Types', () => {
      expect(isTypedArray(new Int8Array(8))).toBeTrue();
      expect(isTypedArray(new Int16Array(16))).toBeTrue();
      expect(isTypedArray(new Int32Array(32))).toBeTrue();
    });

    it('should return true when testing against any Uint Array Types', () => {
      expect(isTypedArray(new Uint8Array(8))).toBeTrue();
      expect(isTypedArray(new Uint16Array(16))).toBeTrue();
      expect(isTypedArray(new Uint32Array(32))).toBeTrue();
      expect(isTypedArray(new Uint8ClampedArray(8))).toBeTrue();
    });

    it('should return true when testing against any Float Array Types', () => {
      expect(isTypedArray(new Float32Array(32))).toBeTrue();
      expect(isTypedArray(new Float64Array(64))).toBeTrue();
    });

    it('should return true when testing against any Data Views', () => {
      expect(isTypedArray(new DataView(new ArrayBuffer(16)))).toBeTrue();
    });

    it('should return true when testing against any Array Buffer', () => {
      expect(isTypedArray(new ArrayBuffer(16))).toBeTrue();
    });

    it('should return false when testing against any other primitive type', () => {
      expect(isTypedArray(666)).toBeFalse();
      expect(isTypedArray('batata')).toBeFalse();
    });

    it('should return false when testing against any other object', () => {
      expect(isTypedArray({})).toBeFalse();
      expect(isTypedArray(new Object())).toBeFalse();
    });

    it('should return false when testing against any non typed array', () => {
      expect(isTypedArray([1, 2, 3])).toBeFalse();
      expect(isTypedArray([true, 'eita', {}])).toBeFalse();
    });
  });

  describe('Encrypting Values', () => {
    it('should return the encrypted the given value and a nonce when using strings', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const [cryptoValue, nonce] = await encryptValue('any data', cryptoKey);
      expect(cryptoValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBeInstanceOf(Uint8Array);
    });

    it('should return the encrypted the given value and a nonce when using any typed array', async () => {
      const originalData = new Uint8Array(8);
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const [cryptoValue, nonce] = await encryptValue(originalData, cryptoKey);
      expect(cryptoValue).not.toEqual(originalData);
      expect(cryptoValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBeInstanceOf(Uint8Array);
    });

    it('should return the encrypted the given value and a nonce when a custom AES algorithm', async () => {
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt(), {
        name: 'AES-CBC',
        length: 256,
      });
      const customAlgorithm = { name: 'AES-CBC', iv: generateNonce() };
      const [cryptoValue, nonce] = await encryptValue('any data', cryptoKey, customAlgorithm);
      expect(cryptoValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBe(customAlgorithm.iv);
    });

    it('should return the encrypted the given value and a null nonce when a custom algorithm without iv', async () => {
      const cryptoKey = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt'],
      );
      const customAlgorithm = { name: 'RSA-OAEP' };
      const [cryptoValue, nonce] = await encryptValue(
        'any data',
        cryptoKey.publicKey,
        customAlgorithm,
      );
      expect(cryptoValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBeNull();
    });
  });

  describe('Decrypting Values', () => {
    it('should decrypt the given value using the original nonce', async () => {
      const originalData = 'any data';
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const [cryptoValue, nonce] = await encryptValue(originalData, cryptoKey);
      const decryptedValue = await decryptValue(cryptoValue, cryptoKey, nonce);
      expect(originalData).toEqual(decode(decryptedValue));
    });

    it('should decrypt the given value using the original nonce when using any typed array', async () => {
      const originalData = new Uint8Array([1, 9, 69, 666]);
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const [cryptoValue, nonce] = await encryptValue(originalData, cryptoKey);
      const decryptedValue = await decryptValue(cryptoValue, cryptoKey, nonce);
      expect(originalData).toEqual(new Uint8Array(decryptedValue));
    });

    it('should decrypt the given value with a custom algorithm', async () => {
      const originalData = 'any data';
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt(), {
        name: 'AES-CBC',
        length: 256,
      });
      const customAlgorithm = { name: 'AES-CBC', iv: generateNonce() };
      const [cryptoValue] = await encryptValue('any data', cryptoKey, customAlgorithm);
      const decryptedValue = await decryptValue(cryptoValue, cryptoKey, customAlgorithm);
      expect(originalData).toEqual(decode(decryptedValue));
    });

    it('should not decrypt the given value using incorrect nonce', async () => {
      const originalData = 'any data';
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const [cryptoValue] = await encryptValue(originalData, cryptoKey);
      const decryptOperation = decryptValue(cryptoValue, cryptoKey, generateNonce());
      await expectAsync(decryptOperation).toBeRejectedWithError();
    });

    it('should not decrypt the given value using incorrect crypto key', async () => {
      const originalData = 'any data';
      const baseKey = await generateBaseCryptoKey('any raw key');
      const cryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const [cryptoValue, nonce] = await encryptValue(originalData, cryptoKey);
      const wrongCryptoKey = await deriveCryptKey(baseKey, generateSalt());
      const error: Error = await decryptValue(cryptoValue, wrongCryptoKey, nonce).catch(e => e);
      expect(error.name).toBe('OperationError');
    });
  });

  describe('Random Values', () => {
    it('should generate a random value as a typed array with 8 random bytes by default', () => {
      const subject = generateRandomValues();
      expect(subject).toBeInstanceOf(Uint8Array);
      expect(subject.length).toBe(8);
    });

    it('should generate random value with the given byte size', () => {
      const byteSize = 69;
      const subject = generateRandomValues(byteSize);
      expect(subject.length).toBe(byteSize);
    });

    it('should generate a nonce as a typed array with 16 random bytes by default', () => {
      const subject = generateNonce();
      expect(subject).toBeInstanceOf(Uint8Array);
      expect(subject.length).toBe(16);
    });

    it('should generate nonce with the given byte size', () => {
      const byteSize = 69;
      const subject = generateNonce(byteSize);
      expect(subject.length).toBe(byteSize);
    });

    it('should generate a salt as a typed array with 8 random bytes by default', () => {
      const subject = generateSalt();
      expect(subject).toBeInstanceOf(Uint8Array);
      expect(subject.length).toBe(8);
    });

    it('should generate salt with the given byte size', () => {
      const byteSize = 69;
      const subject = generateSalt(byteSize);
      expect(subject.length).toBe(byteSize);
    });
  });

  describe('Encoding / Decoding', () => {
    it('should encode a string to typed array', () => {
      expect(encode('any string')).toBeInstanceOf(Uint8Array);
    });

    it('should check if it is already a typed array and just return it', () => {
      const originalValue = [1, 5, 10];
      const typedArray = new Uint8Array(originalValue);
      expect(encode(typedArray)).toEqual(new Uint8Array(originalValue));
    });

    it('should decode a typed array to string', () => {
      expect(decode(new Uint8Array([1, 5, 10]))).toBeInstanceOf(String);
    });

    it('should check if it is already a string and just return it', () => {
      const data = 'any string';
      expect(decode(data)).toBe(data);
    });

    it('should be able to decode an encoded value and get the original value', () => {
      const data = 'any string';
      expect(decode(encode(data))).toBe(data);
    });
  });

  describe('Hash Creation', () => {
    it('should generate a hash in a typed array of the input value', async () => {
      const subject = await generateHash('any string');
      expect(subject).toBeInstanceOf(ArrayBuffer);
    });

    it('should generate a hash in a typed array of another typed array', async () => {
      const originalValue = new Uint8Array([1, 5, 10]);
      const subject = await generateHash(originalValue);
      expect(subject).toBeInstanceOf(ArrayBuffer);
      expect(new Uint8Array(subject)).not.toEqual(originalValue);
    });

    it('should generate the same hash for the same input', async () => {
      const originalValue = 'any string';
      const hash1 = await generateHash(originalValue);
      const hash2 = await generateHash(originalValue);
      expect(new Uint8Array(hash1)).toEqual(new Uint8Array(hash2));
    });

    it('should generate the same hash for the same input in different algorithms', async () => {
      const originalValue = 'any string';
      const hash1 = await generateHash(originalValue, 'SHA-1');
      const hash2 = await generateHash(originalValue, 'SHA-256');
      expect(new Uint8Array(hash1)).not.toEqual(new Uint8Array(hash2));
    });

    it('should generate different hash for different inputs', async () => {
      const hash1 = await generateHash('first input');
      const hash2 = await generateHash('second input');
      expect(new Uint8Array(hash1)).not.toEqual(new Uint8Array(hash2));
    });

    it('should be able to uso other hash algorithms', async () => {
      const subject = await generateHash('any string', { name: 'SHA-1' });
      expect(subject).toBeInstanceOf(ArrayBuffer);
    });
  });
});
