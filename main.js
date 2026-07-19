const fs = require("fs");
const path = require("path");

const detectFormat = require("./utils/detectFormat");

const wallet = JSON.parse(
    fs.readFileSync("encrypted.json", "utf8")
);

const passwords = fs
    .readFileSync("passwords.txt", "utf8")
    .split("\n")
    .map(x => x.trim())
    .filter(Boolean);

function cleanText(str) {
    return str
        // ta bort null-bytes och andra icke-printbara styrtecken (behåll \n, \r, \t)
        .replace(/[^\x20-\x7E\n\r\t]/g, "")
        .trim();
}

function getOutputPath() {
    const outputDir = path.join(__dirname, "output");

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    let filename = "decrypted.txt";
    let counter = 1;

    while (fs.existsSync(path.join(outputDir, filename))) {
        filename = `decrypted${counter}.txt`;
        counter++;
    }

    return path.join(outputDir, filename);
}

async function main() {
    const decryptor = detectFormat(wallet);
    console.log("\n====================");

    for (const password of passwords) {
        console.log(`\n[+] Testar lösenord: ${password}`);

        try {
            const result = await decryptor.decrypt(wallet, password);

            console.log("\n[+] RÄTT LÖSENORD!");
            console.log("[+] Resultat:");
            console.log(result.toString("utf8"));

            console.log("\nHEX:");
            console.log(result.toString("hex"));

            const outputPath = getOutputPath();
            const readableText = cleanText(result.toString("utf8"));
            const content =
                `Lösenord: ${password}\n\n` +
                `${readableText}\n`;

            fs.writeFileSync(outputPath, content, "utf8");
            console.log(`\n[+] Sparad till: ${outputPath}`);

            break;
        } catch (err) {
            console.log("[-] Fel lösenord");
        }
    }
}

main();