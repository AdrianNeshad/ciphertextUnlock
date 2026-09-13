const fs = require("fs");
const path = require("path");
const os = require("os");

const detectFormat = require("./utils/detectFormat");
const crack = require("./crack");

const WALLET_FILE = process.env.WALLET_FILE || "encrypted.json";
const PASSWORDS_FILE = process.env.PASSWORDS_FILE || "passwords.txt";

const wallet = JSON.parse(
    fs.readFileSync(WALLET_FILE, "utf8")
);

const passwords = fs
    .readFileSync(PASSWORDS_FILE, "utf8")
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

    const workerCount = process.env.WORKERS
        ? Math.max(1, parseInt(process.env.WORKERS, 10))
        : Math.max(1, os.cpus().length);

    console.log("\n====================");

    // Brute-forcen körs parallellt över flera kärnor, men onAttempt anropas i
    // exakt lösenordsordning så att loggen ser ut som en seriell körning.
    const found = await crack({
        wallet,
        passwords,
        workerCount,
        onAttempt: (index, ok) => {
            console.log(`\n[+] Testar lösenord: ${passwords[index]}`);
            if (!ok) {
                console.log("[-] Fel lösenord");
            }
        }
    });

    if (!found) {
        return;
    }

    const result = await decryptor.decrypt(wallet, found.password);

    console.log(`\n[34m[+] RÄTT LÖSENORD!`);
    console.log("[+] Resultat:[32m");
    console.log(result.toString("utf8"));

    console.log("\n[0mHEX:");
    console.log(result.toString("hex"));

    const outputPath = getOutputPath();
    const readableText = cleanText(result.toString("utf8"));
    const content =
        `Lösenord: ${found.password}\n\n` +
        `${readableText}\n`;

    fs.writeFileSync(outputPath, content, "utf8");
    console.log(`\n[+] Sparad till: ${outputPath}`);
}

main();
