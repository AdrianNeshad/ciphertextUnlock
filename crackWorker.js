const { parentPort, workerData } = require("worker_threads");

// Tysta all logg från decrypt-vägen inuti workern så att N kärnor inte
// spammar terminalen. Utskriften sköts uteslutande av main-tråden, i ordning.
console.log = () => {};

const detectFormat = require("./utils/detectFormat");

const { wallet, passwords } = workerData;

// Delad räknare mellan alla workers:
//   counter[0] = nästa lösenordsindex att testa (hämtas atomärt)
//   counter[1] = hittad-flagga (1 = någon har hittat rätt lösenord)
const counter = new Int32Array(workerData.shared);

const decryptor = detectFormat(wallet);
const n = passwords.length;

(async () => {
    for (;;) {
        // Avbryt direkt om en annan worker redan hittat lösenordet.
        if (Atomics.load(counter, 1) === 1) {
            break;
        }

        // Hämta nästa lediga index atomärt (arbetsstöld = jämn lastbalans).
        const i = Atomics.add(counter, 0, 1);
        if (i >= n) {
            break;
        }

        let ok = false;
        try {
            await decryptor.decrypt(wallet, passwords[i]);
            ok = true;
        } catch (_) {
            ok = false;
        }

        // Rapportera varje försök till main så att loggen kan skrivas i ordning.
        parentPort.postMessage({ type: "attempt", index: i, ok });

        if (ok) {
            Atomics.store(counter, 1, 1); // signalera stopp till övriga
            break;
        }
    }

    parentPort.postMessage({ type: "done" });
})();
