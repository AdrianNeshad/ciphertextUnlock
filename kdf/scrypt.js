const scrypt =
    require("scrypt-js");



module.exports =
    async function (
        password,
        params
    ) {


        return Buffer.from(

            await scrypt.scrypt(

                Buffer.from(password),

                Buffer.from(
                    params.salt,
                    "hex"
                ),

                params.n,

                params.r,

                params.p,

                params.dklen

            )

        );


    }