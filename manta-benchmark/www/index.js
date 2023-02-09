import {
  Context,
  prove_to_private,
  prove_private_transfer,
  prove_to_public,
} from "wasm-prover";
import { buildPoseidon } from "circomlibjs/src/poseidon_wasm.js";

const pre = document.getElementById("wasm-prover");

const REPEAT = 5;

// Computes the median of an array
const median = (arr) => {
  const mid = Math.floor(arr.length / 2),
    nums = [...arr].sort((a, b) => a - b);
  return arr.length % 2 !== 0 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
};

function bench_prove_to_private() {
  const context = new Context();
  const perf = Array.from({ length: REPEAT }, (_, i) => {
    const t0 = performance.now();
    prove_to_private(context);
    const t1 = performance.now();
    return t1 - t0;
  });
  return `prove to_private performance: ${median(perf)} ms \n`;
}

function bench_prove_private_transfer() {
  const context = new Context();
  const perf = Array.from({ length: REPEAT }, (_, i) => {
    const t0 = performance.now();
    prove_private_transfer(context);
    const t1 = performance.now();
    return t1 - t0;
  });
  return `prove private transfer performance: ${median(perf)} ms \n`;
}

function bench_prove_to_public() {
  const context = new Context();
  const perf = Array.from({ length: REPEAT }, (_, i) => {
    const t0 = performance.now();
    prove_to_public(context);
    const t1 = performance.now();
    return t1 - t0;
  });
  return `prove to_public performance: ${median(perf)} ms \n`;
}

const REPEAT_POSEIDON = 1000;

async function bench_poseidon_js() {
  let poseidonWasm = await buildPoseidon();
  const inp = [1, 2];
  const st = 0;
  const nOut = 1;
  const perf = Array.from({ length: REPEAT_POSEIDON }, (_, i) => {
    const t0 = performance.now();
    poseidonWasm(inp, st, nOut);
    const t1 = performance.now();
    return t1 - t0;
  });
  return `poseidon_js performance: ${median(perf)} ms \n`;
}

// benchmarks proof time for to_private
pre.textContent = bench_prove_to_private();

// benchmarks proof time for private transfer
pre.textContent += bench_prove_private_transfer();

// benchmarks proof time for to_public
pre.textContent += bench_prove_to_public();

// benchmarks proof for poseidon hash
bench_poseidon_js().then(function (resolvedValue) {
  pre.textContent += resolvedValue;
});
