# Web Crypto Tools

<p>
  <a
    href="https://github.com/willgm/web-crypto-tools/actions"
    target="_blank"
  >
    <img
      alt="Build"
      src="https://img.shields.io/github/workflow/status/willgm/web-crypto-tools/CI"
    />
  </a>
  <a
    href="https://www.npmjs.com/package/@webcrypto/tools"
    target="_blank"
  >
    <img
      alt="Version"
      src="https://img.shields.io/github/package-json/v/willgm/web-crypto-tools"
    />
  </a>
  <a
    href="https://github.com/willgm/web-crypto-tools/blob/master/LICENSE"
    target="_blank"
  >
    <img
      src="https://img.shields.io/badge/license-MIT-blue.svg"
      alt="web-crypto-tools is released under the MIT license"
    />
  </a>
  <a
    href="https://github.com/willgm/web-crypto-tools/graphs/contributors"
    target="_blank"
  >
    <img
      alt="Contributors"
      src="https://img.shields.io/github/contributors/willgm/web-crypto-tools.svg"
    />
  </a>
</p>

> This project is a set of tools to facilitate and give good defaults for use of the native **[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)**.

This project depends on the browser implementation of [Crypto API](https://caniuse.com/#feat=cryptography) and [TextEncoder API](https://caniuse.com/#feat=textencoder), which are both current implemented on all green browsers. If you do need to support IE or any older browser, you should look for available polyfills.

The native browser implementation of crypto algorithms are much more fast and secure than any other JavaScript library out there. But at the same time, it is a low level API that relies on you to decide every little detail of it, so this project will give you good defaults and a better developer experience, and still let you decide if you prefer use other algorithms or extra protections. Be aware that, even if this project facilitates the use of the Web Crypto API, it will not prevent you from make any mistakes if you have no idea about cryptography concepts, so take your time to study a little before use it in a real project.

In the end, this is a simple collection of stateless functions, values and types, that can be individually imported and used. The minified project has currently only about 3kb in total and it is also tree-shaking friendly, so you can end up using even less.

## :gear: Usage

### Install it at your project

```bash
npm install @webcrypto/tools --save
```

### Encrypt everything

```ts
import {
  generateBaseCryptoKey,
  deriveCryptKey,
  generateSalt,
  encryptValue,
  decryptValue,
  decode,
} from '@webcrypto/tools';

// get any data, string or typed arrays
const originalData = 'any data';

// create a secure base key that cannot be reverted to the original key value
const baseKey = await generateBaseCryptoKey('any raw key');

// create new keys for each crypto operation from the base key
const cryptoKey = await deriveCryptKey(baseKey, generateSalt());

// encrypt any value with military level security
const [cryptoValue, nonce] = await encryptValue(originalData, cryptoKey);

// decrypt your value when necessary
const decryptedValue = await decryptValue(cryptoValue, cryptoKey, nonce);

// the decrypted value should be the same of the original
expect(originalData).toEqual(decode(decryptedValue));
```

## :book: Documentation

The [documentation with all available API and options](https://willgm.github.io/web-crypto-tools/) at our GitHub Pages.

The [test cases](https://github.com/willgm/web-crypto-tools/tree/master/test) are also quite readable and can be used as example for all the possible API uses.

## License

[MIT](https://github.com/willgm/web-crypto-tools/blob/master/LICENSE)
