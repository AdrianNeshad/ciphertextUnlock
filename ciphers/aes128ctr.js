const crypto =
    require("crypto");

module.exports =
    function (
        data,
        key,
        iv
    ) {
        const decipher =
            crypto.createDecipheriv(
                "aes-128-ctr",
                key,
                iv
            );

        return Buffer.concat([
            decipher.update(data),
            decipher.final()
        ]);
    }