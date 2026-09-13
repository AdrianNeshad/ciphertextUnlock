const scrypt = require("../kdf/scrypt");
const pbkdf2 = require("../kdf/pbkdf2");
const aes = require("../ciphers/aes");

const { verifyEthereumMAC } = require("../validators/mac");

// Web3 Secret Storage version 1 (äldre exporter från C++-klienten/Mist).
// Skiljer sig från V3 genom kapitaliserade fältnamn, aes-128-cbc som
// cipher och att saltet ligger i Crypto.Salt i stället för i
// kdf-parametrarna. MAC beräknas på samma sätt som i V3.

// Normalisera V1:s kdf-parametrar till samma form som övriga KDF:er väntar.
function normalizeParams(kdf, raw, saltHex) {
    const params = { salt: saltHex };

    if (kdf === "scrypt") {
        params.n = raw.n || raw.N;
        params.r = raw.r || raw.R;
        params.p = raw.p || raw.P;
        params.dklen = raw.dklen || raw.dkLen;
    } else {
        params.c = raw.c || raw.iterations;
        params.dklen = raw.dklen || raw.dkLen;
        params.prf = raw.prf;
    }

    return params;
}

exports.decrypt = async function (wallet, password) {
    const c = wallet.Crypto || wallet.crypto;

    const kdf = (c.KeyHeader.Kdf || "scrypt").toLowerCase();
    const params = normalizeParams(kdf, c.KeyHeader.KdfParams, c.Salt);

    const derivedKey =
        kdf === "scrypt"
            ? await scrypt(password, params)
            : pbkdf2(password, params);

    const ciphertext = Buffer.from(c.CipherText, "hex");

    if (!verifyEthereumMAC(derivedKey, ciphertext, c.MAC)) {
        throw Error("Fel MAC");
    }

    const iv = Buffer.from(c.IV, "hex");

    return aes(
        "aes-128-cbc",
        ciphertext,
        derivedKey.slice(0, 16),
        iv
    );
};
