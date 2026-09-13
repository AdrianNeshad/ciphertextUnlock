"use strict";

// Ren-JS Keccak-256 (Ethereum-varianten med original-padding 0x01),
// helt utan externa beroenden. Ersätter det native "keccak"-paketet så att
// repot kan köras offline på valfri plattform utan npm install eller
// kompilering. Används bara för korta indata (MAC-verifiering och
// adresshärledning), så den enkla BigInt-implementationen är snabb nog.

const MASK = (1n << 64n) - 1n;

const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];

// Rotationsoffset r[x][y].
const ROT = [
    [0n, 36n, 3n, 41n, 18n],
    [1n, 44n, 10n, 45n, 2n],
    [62n, 6n, 43n, 15n, 61n],
    [28n, 55n, 25n, 21n, 56n],
    [27n, 20n, 39n, 8n, 14n]
];

const rotl = (v, n) => ((v << n) | (v >> (64n - n))) & MASK;

function keccakF(A) {
    for (let round = 0; round < 24; round++) {
        // Theta
        const C = new Array(5);
        for (let x = 0; x < 5; x++) {
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
        }
        const D = new Array(5);
        for (let x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n);
        }
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                A[x][y] ^= D[x];
            }
        }

        // Rho + Pi
        const B = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n],
                   [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                B[y][(2 * x + 3 * y) % 5] = rotl(A[x][y], ROT[x][y]);
            }
        }

        // Chi
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y] & MASK) & B[(x + 2) % 5][y]);
            }
        }

        // Iota
        A[0][0] ^= RC[round];
    }
}

function keccak256(input) {
    const msg = Buffer.isBuffer(input) ? input : Buffer.from(input);
    const RATE = 136; // byte (1088 bitar)

    // pad10*1 med Keccak-original-padding (0x01 ... 0x80).
    const q = RATE - (msg.length % RATE);
    const tail = Buffer.alloc(q);
    tail[0] = 0x01;
    tail[q - 1] |= 0x80;
    const padded = Buffer.concat([msg, tail]);

    // 5x5 lane-state (lane-index i = x + 5y).
    const A = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n],
               [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];

    for (let off = 0; off < padded.length; off += RATE) {
        for (let i = 0; i < RATE / 8; i++) {
            let lane = 0n;
            for (let j = 0; j < 8; j++) {
                lane |= BigInt(padded[off + i * 8 + j]) << (8n * BigInt(j));
            }
            A[i % 5][Math.floor(i / 5)] ^= lane;
        }
        keccakF(A);
    }

    // Squeeze 32 byte (4 lanes) little-endian.
    const out = Buffer.alloc(32);
    for (let i = 0; i < 4; i++) {
        let lane = A[i % 5][Math.floor(i / 5)];
        for (let j = 0; j < 8; j++) {
            out[i * 8 + j] = Number(lane & 0xffn);
            lane >>= 8n;
        }
    }
    return out;
}

module.exports = keccak256;
