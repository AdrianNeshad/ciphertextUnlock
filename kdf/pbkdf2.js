const crypto =
    require("crypto");


module.exports =
    function (
        password,
        params
    ) {


        return crypto.pbkdf2Sync(

            password,

            Buffer.from(
                params.salt,
                "hex"
            ),

            params.iterations,

            params.dklen,

            "sha256"

        );


    }