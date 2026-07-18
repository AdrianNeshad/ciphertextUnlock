const fs = require("fs");

const detectFormat =
    require("./utils/detectFormat");

const wallet =
    JSON.parse(
        fs.readFileSync(
            "encrypted.json",
            "utf8"
        )
    );

const passwords =
    fs.readFileSync(
        "passwords.txt",
        "utf8"
    )
        .split("\n")
        .map(x => x.trim())
        .filter(Boolean);

async function main() {
    const decryptor =
        detectFormat(wallet);
    console.log("\n====================");

    for (const password of passwords) {
        console.log(
            `\n[+] Testar lösenord: ${password}`
        );

        try {
            const result =
                await decryptor.decrypt(
                    wallet,
                    password
                );
            console.log(
                "\n[+] RÄTT LÖSENORD!"
            );

            console.log(
                "[+] Resultat:"
            );

            console.log(
                result.toString("utf8")
            );

            console.log(
                "\nHEX:"
            );

            console.log(
                result.toString("hex")
            );
            break;
        }
        catch (err) {
            console.log(
                "[-] Fel lösenord"
            );
        }
    }
}

main();