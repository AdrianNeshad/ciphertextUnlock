const crypto =
    require("crypto");

const aes256cbc =
    require("../ciphers/aes256cbc");

// Formatet anger explicit KDF (PBKDF2 + iterationsantal) via
// keyMetadata, så till skillnad från wallets/cryptojs.js behöver
// vi inte gissa oss fram där. Vad gäller cipher-läge testar vi
// AES-256-GCM först (WebCrypto-konventionen: de sista 16 byten av
// ciphertext är auth-taggen, vilket ger en riktig korrekthetskontroll
// via GCM:s autentisering) och faller tillbaka på AES-256-CBC.
exports.decrypt =
    async function (wallet, password) {
        const salt =
            Buffer.from(
                wallet.salt,
                "base64"
            );

        const iv =
            Buffer.from(
                wallet.iv,
                "hex"
            );

        const raw =
            Buffer.from(
                wallet.cipher,
                "base64"
            );

        const iterations =
            wallet.keyMetadata.params.iterations;

        const key =
            crypto.pbkdf2Sync(
                password,
                salt,
                iterations,
                32,
                "sha256"
            );

        try {
            const authTag =
                raw.slice(raw.length - 16);

            const ciphertext =
                raw.slice(0, raw.length - 16);

            const decipher =
                crypto.createDecipheriv(
                    "aes-256-gcm",
                    key,
                    iv
                );

            decipher.setAuthTag(authTag);

            return Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);
        } catch (err) {
            return aes256cbc(raw, key, iv);
        }
    }
