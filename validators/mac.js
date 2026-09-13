const keccak256 = require("../utils/keccak256");

function verifyEthereumMAC(
    key,
    ciphertext,
    storedMac
) {
    const calculated =
        keccak256(
            Buffer.concat([
                key.slice(16, 32),
                ciphertext
            ])
        ).toString("hex");

    return calculated === storedMac;
}

module.exports = {
    verifyEthereumMAC
};
