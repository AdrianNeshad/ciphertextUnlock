const ethereum = require("../wallets/ethereum");
const ethereumV1 = require("../wallets/ethereumV1");
const ethereumPresale = require("../wallets/ethereumPresale");
const generic = require("../wallets/generic");
const cryptojs = require("../wallets/cryptojs");
const keyMetadataVault = require("../wallets/keyMetadataVault");

module.exports = function (wallet) {
    console.log("\n[+] Identifierar format...");

    // Ethereum presale-plånbok (förköpet 2014).
    if (wallet.encseed && wallet.ethaddr) {
        console.log("[+] Ethereum presale-plånbok (encseed/ethaddr)");
        return ethereumPresale;
    }

    // PBKDF2-vault (eget format: cipher/iv/salt + keyMetadata).
    if (
        wallet.cipher &&
        wallet.iv &&
        wallet.salt &&
        wallet.keyMetadata &&
        wallet.keyMetadata.algorithm === "PBKDF2"
    ) {
        console.log("[+] PBKDF2-vault-format (cipher/iv/salt/keyMetadata)");
        return keyMetadataVault;
    }

    // CryptoJS (eget format: cipher/iv/salt utan crypto-struktur).
    if (
        wallet.cipher &&
        wallet.iv &&
        wallet.salt &&
        !wallet.crypto &&
        !wallet.Crypto
    ) {
        console.log("[+] CryptoJS-format (cipher/iv/salt)");
        return cryptojs;
    }

    const crypto = wallet.crypto || wallet.Crypto;

    if (!crypto) {
        throw Error("Ingen crypto-struktur hittades");
    }

    // Web3 Secret Storage V1 (kapitaliserade fält: CipherText/KeyHeader/Salt).
    if (crypto.KeyHeader || crypto.CipherText) {
        console.log("[+] Ethereum keystore V1");
        return ethereumV1;
    }

    // Web3 Secret Storage V3 (scrypt eller pbkdf2, valfri AES-variant).
    if (crypto.ciphertext && crypto.kdf) {
        console.log(
            `[+] Ethereum keystore V3 (${crypto.kdf} / ${crypto.cipher || "aes-128-ctr"})`
        );
        return ethereum;
    }

    console.log("[+] Generic AES");
    return generic;
};
