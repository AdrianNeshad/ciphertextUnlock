const scrypt = require("../kdf/scrypt");
const pbkdf2 = require("../kdf/pbkdf2");
const aes = require("../ciphers/aes");

const { verifyEthereumMAC } = require("../validators/mac");

// Web3 Secret Storage Definition, version 3. Det är standardformatet för
// UTC/keystore-filer från geth, MetaMask, MyEtherWallet, TrustWallet m.fl.
// Här stöds båda KDF:erna i specen (scrypt + pbkdf2) samt samtliga
// cipher-varianter som förekommer i praktiken (aes-128/256 i ctr/cbc).

async function deriveKey(password, kdf, params) {
    switch ((kdf || "").toLowerCase()) {
        case "scrypt":
            return scrypt(password, params);
        case "pbkdf2":
            return pbkdf2(password, params);
        default:
            throw Error("Okänd KDF: " + kdf);
    }
}

// AES-128-* använder de första 16 byten av den härledda nyckeln,
// AES-256-* de första 32.
function cipherKey(cipher, derivedKey) {
    return cipher.includes("256")
        ? derivedKey.slice(0, 32)
        : derivedKey.slice(0, 16);
}

exports.decrypt = async function (wallet, password) {
    const c = wallet.crypto || wallet.Crypto;

    const derivedKey = await deriveKey(
        password,
        c.kdf,
        c.kdfparams
    );

    const ciphertext = Buffer.from(c.ciphertext, "hex");

    // MAC = keccak256(derivedKey[16:32] || ciphertext). Fel lösenord ger
    // fel nyckel och därmed fel MAC, vilket är vår korrekthetskontroll.
    if (!verifyEthereumMAC(derivedKey, ciphertext, c.mac)) {
        throw Error("Fel MAC");
    }

    const cipher = (c.cipher || "aes-128-ctr").toLowerCase();
    const iv = Buffer.from(c.cipherparams.iv, "hex");

    return aes(
        cipher,
        ciphertext,
        cipherKey(cipher, derivedKey),
        iv
    );
};
