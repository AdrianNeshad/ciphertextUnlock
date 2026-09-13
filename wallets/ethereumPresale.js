const crypto = require("crypto");
const keccak = require("keccak");

const aes = require("../ciphers/aes");

// Ethereum presale-plånbok (förköpet 2014). Formatet saknar MAC men
// innehåller den förväntade adressen i "ethaddr", så korrektheten
// verifieras genom att härleda adressen ur den dekrypterade nyckeln.

function keccak256(buf) {
    return keccak("keccak256").update(buf).digest();
}

// Härled Ethereum-adress (20 byte, hex) ur en privat nyckel (32 byte).
function addressFromPrivateKey(privateKey) {
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(privateKey);

    const publicKey = ecdh.getPublicKey(); // 0x04 || X || Y
    return keccak256(publicKey.slice(1)).slice(-20).toString("hex");
}

exports.decrypt = async function (wallet, password) {
    const encseed = Buffer.from(wallet.encseed, "hex");

    // Nyckeln härleds med lösenordet både som lösenord och som salt.
    const derivedKey = crypto
        .pbkdf2Sync(
            Buffer.from(password),
            Buffer.from(password),
            2000,
            32,
            "sha256"
        )
        .slice(0, 16);

    // De första 16 byten av encseed är IV, resten är ciphertext.
    const seed = aes(
        "aes-128-cbc",
        encseed.slice(16),
        derivedKey,
        encseed.slice(0, 16)
    );

    const privateKey = keccak256(seed);

    // Jämför härledd adress mot den som lagras i plånboken.
    const expected = wallet.ethaddr.toLowerCase().replace(/^0x/, "");
    if (addressFromPrivateKey(privateKey) !== expected) {
        throw Error("Adress stämmer inte");
    }

    return privateKey;
};
