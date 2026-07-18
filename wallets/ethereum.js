const scrypt =
    require("../kdf/scrypt");

const aes128 =
    require("../ciphers/aes128ctr");

const {
    verifyEthereumMAC
}
    =
    require("../validators/mac");

exports.decrypt =
    async function (wallet, password) {
        const c =
            wallet.crypto ||
            wallet.Crypto;

        const key =
            await scrypt(
                password,
                c.kdfparams
            );

        const ciphertext =
            Buffer.from(
                c.ciphertext,
                "hex"
            );

        const valid =
            verifyEthereumMAC(
                key,
                ciphertext,
                c.mac
            );

        if (!valid) {
            throw Error(
                "Fel MAC"
            );
        }

        const iv =
            Buffer.from(
                c.cipherparams.iv,
                "hex"
            );

        const decrypted =
            aes128(
                ciphertext,
                key.slice(0, 16),
                iv
            );
        return decrypted;
    }