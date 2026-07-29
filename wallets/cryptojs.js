const crypto =
    require("crypto");

const aes128cbc =
    require("../ciphers/aes128cbc");

const aes256cbc =
    require("../ciphers/aes256cbc");

// Formatet saknar MAC/checksum, så vi vet inte i förväg
// vilken nyckelstorlek, iterationsantal eller hash som
// användes. Vi provar de vanligaste CryptoJS-varianterna
// och litar på att PKCS7-paddningen (som Node kastar fel på
// vid fel nyckel) fungerar som en de-facto korrekthetskontroll.
const KEY_SIZES = [16, 32];
const ITERATIONS = [1, 1000, 2048, 5000, 10000, 100000];
const HASHES = ["sha1", "sha256"];

function isMostlyPrintable(buf) {
    if (buf.length === 0) {
        return false;
    }

    const text = buf.toString("utf8");
    let printable = 0;

    for (const ch of text) {
        const code = ch.charCodeAt(0);
        if (
            (code >= 0x20 && code <= 0x7e) ||
            code === 0x0a ||
            code === 0x0d ||
            code === 0x09
        ) {
            printable++;
        }
    }

    return printable / text.length > 0.9;
}

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

        const ciphertext =
            Buffer.from(
                wallet.cipher,
                "base64"
            );

        for (const keySize of KEY_SIZES) {
            for (const iterations of ITERATIONS) {
                for (const hash of HASHES) {
                    const key =
                        crypto.pbkdf2Sync(
                            password,
                            salt,
                            iterations,
                            keySize,
                            hash
                        );

                    try {
                        const decrypted =
                            keySize === 16
                                ? aes128cbc(ciphertext, key, iv)
                                : aes256cbc(ciphertext, key, iv);

                        if (isMostlyPrintable(decrypted)) {
                            console.log(
                                `[+] Match: keySize=${keySize * 8} bit, iterations=${iterations}, hash=${hash}`
                            );
                            return decrypted;
                        }
                    } catch (err) {
                        // Fel paddning -> fel nyckel/parametrar, testa nästa kombination
                    }
                }
            }
        }

        throw Error(
            "Fel lösenord"
        );
    }
