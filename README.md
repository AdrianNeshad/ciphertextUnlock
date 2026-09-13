<h1 id="title">Ciphertext Unlock</h1>

1.  The script reads the content in the file `encrypted.json`, which contains the necessary info to decrypt the original content.
2.  It then tries the passwords from `passwords.txt`.
3.  If a password is correct it decrypts the ciphertext and extracts the decrypted value to `output/decrypted.txt`.

The repository already includes a `encrypted.json` file and the corresponding password in `passwords.txt` to test out the script.

### **Requirements**

Only **Node.js** (v12+). There are **no dependencies** — no `npm install`, no native build, no network. Clone the repo and run. Everything (including scrypt and keccak256) is implemented with Node built-ins or bundled pure-JS.

### **Run the script**

```
node main.js
```

The brute-force runs in parallel across all CPU cores using `worker_threads` and stops as soon as a password matches. Optional overrides via environment variables:

```
WORKERS=4 WALLET_FILE=mywallet.json PASSWORDS_FILE=list.txt node main.js
```

### **Supported formats & algorithms**

The format is detected automatically from the structure of `encrypted.json` (see [`utils/detectFormat.js`](utils/detectFormat.js)).

**Ethereum keystores — all variants:**

| Format | Detected by | Key derivation (KDF) | Cipher | Integrity / password check |
| --- | --- | --- | --- | --- |
| **Web3 Secret Storage V3** <br>(geth, MetaMask, MyEtherWallet, TrustWallet, UTC-- files) | `crypto.ciphertext` + `crypto.kdf` | `scrypt` (`n`/`r`/`p`/`dklen`) **and** `pbkdf2` (`c`, `prf: hmac-sha256`) | `aes-128-ctr`, `aes-256-ctr`, `aes-128-cbc`, `aes-256-cbc` | `keccak256(key[16:32] ‖ ciphertext)` MAC |
| **Web3 Secret Storage V1** <br>(older C++/Mist exports) | `Crypto.KeyHeader` / `Crypto.CipherText` | `scrypt` **and** `pbkdf2` (from `KeyHeader.KdfParams`) | `aes-128-cbc` | `keccak256(key[16:32] ‖ ciphertext)` MAC |
| **Ethereum presale wallet** <br>(2014 pre-sale) | `encseed` + `ethaddr` | `pbkdf2-hmac-sha256`, 2000 iterations (password used as both password and salt) | `aes-128-cbc` | secp256k1 address derived from the key is compared to `ethaddr` (no MAC in this format) |

All Ethereum variants support `crypto` and `Crypto` spelling, and AES-128 vs AES-256 key length is selected automatically from the cipher name.

**Other (non-Ethereum) formats also handled:**

| Format | Detected by | Key derivation (KDF) | Cipher | Integrity / password check |
| --- | --- | --- | --- | --- |
| **PBKDF2 keyMetadata vault** | `cipher`/`iv`/`salt` + `keyMetadata.algorithm = "PBKDF2"` | `pbkdf2-sha256` (iterations from `keyMetadata.params`) | `aes-256-gcm`, falls back to `aes-256-cbc` | GCM authentication tag |
| **CryptoJS blob** | `cipher`/`iv`/`salt`, no `crypto` struct | `pbkdf2` — hash (`sha1`/`sha256`), iteration count and key size are brute-forced | `aes-128-cbc` / `aes-256-cbc` | PKCS#7 padding + printable-text heuristic |
| **Generic AES** | fallback for any other `crypto` struct | — | AES | — |

### **Användaravtal:**

*   Vid lyckad dekryptering av ciphertext är användaren skyldig Adrian (repository owner) en öl.
