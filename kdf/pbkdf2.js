const crypto = require("crypto");

// Översätt PRF-namn ("hmac-sha256") till Nodes hash-namn ("sha256").
function prfToHash(prf) {
    if (!prf) {
        return "sha256";
    }

    const match = /^hmac-(.+)$/i.exec(prf);
    return (match ? match[1] : prf).toLowerCase();
}

module.exports = function (password, params) {
    // Web3 Secret Storage V3 anger iterationsantalet som "c";
    // äldre/egna format använder "iterations".
    const iterations =
        params.c != null ? params.c : params.iterations;

    return crypto.pbkdf2Sync(
        password,
        Buffer.from(params.salt, "hex"),
        iterations,
        params.dklen,
        prfToHash(params.prf)
    );
};
