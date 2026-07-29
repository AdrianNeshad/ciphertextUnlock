const ethereum =
    require("../wallets/ethereum");

const generic =
    require("../wallets/generic");

const cryptojs =
    require("../wallets/cryptojs");

const keyMetadataVault =
    require("../wallets/keyMetadataVault");

module.exports = function (wallet) {
    console.log(
        "\n[+] Identifierar format..."
    );

    if (
        wallet.cipher &&
        wallet.iv &&
        wallet.salt &&
        wallet.keyMetadata &&
        wallet.keyMetadata.algorithm
        ===
        "PBKDF2"
    ) {
        console.log(
            "[+] PBKDF2-vault-format (cipher/iv/salt/keyMetadata)"
        );
        return keyMetadataVault;
    }

    if (
        wallet.cipher &&
        wallet.iv &&
        wallet.salt &&
        !wallet.crypto &&
        !wallet.Crypto
    ) {
        console.log(
            "[+] CryptoJS-format (cipher/iv/salt)"
        );
        return cryptojs;
    }

    const crypto =
        wallet.crypto ||
        wallet.Crypto;

    if (!crypto) {
        throw Error(
            "Ingen crypto struktur hittades"
        );
    }

    console.log(
        "Cipher:",
        crypto.cipher
    );

    console.log(
        "KDF:",
        crypto.kdf
    );

    if (
        crypto.cipher.toLowerCase()
        ===
        "aes-128-ctr"
        &&
        crypto.kdf
        ===
        "scrypt"
    ) {
        console.log(
            "[+] Ethereum / TrustWallet V3"
        );
        return ethereum;
    }

    console.log(
        "[+] Generic AES"
    );
    return generic;
}