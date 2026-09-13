const os = require("os");
const path = require("path");
const { Worker } = require("worker_threads");

// Parallell brute-force över flera CPU-kärnor med worker_threads.
//
// Varje worker delar en atomär räknare (SharedArrayBuffer) och plockar nästa
// lediga lösenordsindex själv. Det ger jämn lastbalansering och alla workers
// stoppar direkt när någon hittar rätt.
//
// onAttempt(index, ok) anropas i exakt stigande index-ordning (0, 1, 2, ...)
// upp till och med första träffen. Resultaten buffras och skrivs ut i ordning
// även om de beräknas parallellt, så loggen blir identisk med en seriell
// körning.
//
// Returnerar en Promise som resolvar till { password, index } vid träff,
// annars null om inget lösenord i listan fungerade.
function crack({ wallet, passwords, workerCount, onAttempt } = {}) {
    return new Promise((resolve, reject) => {
        const n = passwords.length;
        if (n === 0) {
            resolve(null);
            return;
        }

        const cores = workerCount || Math.max(1, os.cpus().length);
        const count = Math.min(cores, n);

        // 2 x Int32: [0] = nästa index, [1] = hittad-flagga.
        const shared = new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT);

        const workers = [];
        let settled = false;
        let finishedWorkers = 0;

        // Buffert för ordnad utskrift: index -> ok.
        const results = new Map();
        let nextEmit = 0;

        const cleanup = () =>
            Promise.all(workers.map(w => w.terminate()));

        const finish = (result, err) => {
            if (settled) {
                return;
            }
            settled = true;
            cleanup().finally(() => (err ? reject(err) : resolve(result)));
        };

        // Skriv ut färdiga resultat i stigande index-ordning tills ett saknas.
        const drain = () => {
            while (results.has(nextEmit)) {
                const ok = results.get(nextEmit);
                results.delete(nextEmit);

                if (onAttempt) {
                    onAttempt(nextEmit, ok);
                }

                if (ok) {
                    finish({ password: passwords[nextEmit], index: nextEmit });
                    return;
                }
                nextEmit++;
            }
        };

        for (let k = 0; k < count; k++) {
            const worker = new Worker(
                path.join(__dirname, "crackWorker.js"),
                { workerData: { wallet, passwords, shared } }
            );
            workers.push(worker);

            worker.on("message", (msg) => {
                if (settled) {
                    return;
                }
                if (msg.type === "attempt") {
                    results.set(msg.index, msg.ok);
                    drain();
                } else if (msg.type === "done") {
                    finishedWorkers++;
                    if (finishedWorkers === count) {
                        drain();
                        finish(null); // alla klara utan träff
                    }
                }
            });

            worker.on("error", (err) => finish(null, err));
        }
    });
}

module.exports = crack;
