const crypto = require("crypto");

// Nodes inbyggda scrypt (OpenSSL) – native och utan extern dependency.
// Ersätter "scrypt-js". maxmem måste rymma scrypt-arbetsminnet
// (~128 * r * N byte) annars kastar Node "memory limit exceeded".
module.exports = function (password, params) {
    const N = params.n;
    const r = params.r;
    const p = params.p;

    const maxmem = 128 * r * (N + p + 2) + (1 << 20);

    return crypto.scryptSync(
        Buffer.from(password),
        Buffer.from(params.salt, "hex"),
        params.dklen,
        { N, r, p, maxmem }
    );
};
