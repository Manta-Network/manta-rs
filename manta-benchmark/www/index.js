import { Context, Proof, prove_mint, prove_private_transfer, prove_reclaim, verify_mint, verify_private_transfer, verify_reclaim } from "wasm-prover";

const pre = document.getElementById("wasm-prover");


// Computes the median of an array
const median = arr => {
    const mid = Math.floor(arr.length / 2),
      nums = [...arr].sort((a, b) => a - b);
    return arr.length % 2 !== 0 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
  };

function bench_construct_context() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const t0 = performance.now();
        const context = new Context();
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `construct Context performance: ${median(perf)} ms \n`;
  return out_text;
}

function bench_prove_mint() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const context = new Context();
        const t0 = performance.now();
        prove_mint(context);
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `prove mint performance: ${median(perf)} ms \n`;
  return out_text;
}

function bench_verify_mint() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const context = new Context();
        const proof = prove_mint(context);
        const t0 = performance.now();
        verify_mint(context, proof);
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `verify mint performance: ${median(perf)} ms \n`;
  return out_text;
}

function bench_prove_private_transfer() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const context = new Context();
        const t0 = performance.now();
        prove_private_transfer(context);
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `prove private transfer performance: ${median(perf)} ms \n`;
  return out_text;
}

function bench_verify_private_transfer() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const context = new Context();
        const proof = prove_private_transfer(context);
        const t0 = performance.now();
        verify_private_transfer(context, proof);
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `verify private transfer performance: ${median(perf)} ms \n`;
  return out_text;
}

function bench_prove_reclaim() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const context = new Context();
        const t0 = performance.now();
        prove_reclaim(context);
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `prove reclaim performance: ${median(perf)} ms \n`;
  return out_text;
}

function bench_verify_reclaim() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const context = new Context();
        const proof = prove_reclaim(context);
        const t0 = performance.now();
        verify_reclaim(context, proof);
        const t1 = performance.now();
        return t1 - t0;
      }
  );
  let out_text = `verify reclaim performance: ${median(perf)} ms \n`;
  return out_text;
}

// benchmarks time for constructing context
// pre.textContent = bench_construct_context();

// benchmarks proof time for mint
pre.textContent = bench_prove_mint();

// // benchmarks verification time for mint
// pre.textContent = bench_verify_mint();

// // benchmarks proof time for private transfer
// pre.textContent = bench_prove_private_transfer();

// // benchmarks verification time for priivate transfer
// pre.textContent = bench_verify_private_transfer();

// // benchmarks proof time for reclaim
// pre.textContent = bench_prove_reclaim();

// // benchmarks verification time for reclaim
// pre.textContent = bench_verify_reclaim();
