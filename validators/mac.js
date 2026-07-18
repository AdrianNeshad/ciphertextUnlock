const keccak =
    require("keccak");

function verifyEthereumMAC(
    key,
    ciphertext,
    storedMac
) {
    const calculated =
        keccak("keccak256")
            .update(
                Buffer.concat([
                    key.slice(16, 32),
                    ciphertext
                ])
            )
            .digest("hex");

    console.log(
        "[+] MAC calculated:",
        calculated
    );

    console.log(
        "[+] MAC stored:",
        storedMac
    );
    return calculated === storedMac;
}

module.exports = {
    verifyEthereumMAC
};