const ethereum =
    require("../wallets/ethereum");

const generic =
    require("../wallets/generic");

module.exports = function (wallet) {
    const crypto =
        wallet.crypto ||
        wallet.Crypto;

    if (!crypto) {
        throw Error(
            "Ingen crypto struktur hittades"
        );
    }

    console.log(
        "\n[+] Identifierar format..."
    );

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