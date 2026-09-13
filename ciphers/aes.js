const crypto = require("crypto");

// Generell AES-dekryptering. Väljer algoritm utifrån namnet i
// keystore-filen (t.ex. "aes-128-ctr", "aes-256-cbc") så att både
// 128/256-bitars nycklar och CTR/CBC-lägen hanteras på ett ställe.
module.exports = function (algorithm, data, key, iv) {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    return Buffer.concat([
        decipher.update(data),
        decipher.final()
    ]);
};
