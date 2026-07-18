const pbkdf2 =
    require("../kdf/pbkdf2");

const aes256 =
    require("../ciphers/aes256ctr");

exports.decrypt =
    async function (wallet, password) {
        const key =
            pbkdf2(
                password,
                wallet.kdf
            );
        const decrypted =
            aes256(
                Buffer.from(
                    wallet.encrypted_seed,
                    "hex"
                ),
                key,
                Buffer.from(
                    wallet.iv,
                    "hex"
                )
            );
        return decrypted;
    }