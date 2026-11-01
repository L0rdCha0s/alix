// Run with the actual upstream js shell and native Alix runtime. No Alix JS
// interpreter or host engine can satisfy this guest's execution evidence.
function hotSum(limit) {
  let value = 0;
  for (let index = 0; index < limit; ++index) value += index;
  return [value, inIon()];
}
let ionObserved = false;
for (let iteration = 0; iteration < 200; ++iteration) {
  const result = hotSum(1000);
  assertEq(result[0], 499500);
  if (result[1] === true) ionObserved = true;
}
assertEq(ionObserved, true);
print("ALIX_SPIDERMONKEY_RUNTIME: JIT PASS ion=1");

for (let iteration = 0; iteration < 8; ++iteration) {
  const objects = Array.from({length: 10000}, (_, index) => ({n: index, s: "value" + index}));
  gc();
  assertEq(objects.reduce((value, object) => value + object.n, 0), 49995000);
  assertEq(objects[9999].s, "value9999");
}
print("ALIX_SPIDERMONKEY_RUNTIME: GC PASS roots=10000 cycles=8");

const binary = wasmTextToBinary(`(module
  (memory (export "memory") 1)
  (func (export "answer") (result i32) i32.const 42)
  (func (export "load") (param i32) (result i32) local.get 0 i32.load))`);
const wasm = new WebAssembly.Instance(new WebAssembly.Module(binary));
assertEq(wasm.exports.answer(), 42);
new Int32Array(wasm.exports.memory.buffer)[0] = 12345;
assertEq(wasm.exports.load(0), 12345);
let trapped = false;
try { wasm.exports.load(65536); }
catch (error) { trapped = error instanceof WebAssembly.RuntimeError; }
assertEq(trapped, true);
print("ALIX_SPIDERMONKEY_RUNTIME: WASM PASS value=42 bounds_trap=1");

const shared = new SharedArrayBuffer(4);
const control = new Int32Array(shared);
setSharedObject(shared);
evalInWorker(`
  const control = new Int32Array(getSharedObject());
  Atomics.store(control, 0, 42);
  Atomics.notify(control, 0);
`);
const waited = Atomics.wait(control, 0, 0, 10000);
assertEq(waited === "ok" || waited === "not-equal", true);
assertEq(Atomics.load(control, 0), 42);
setSharedObject(null);
print("ALIX_SPIDERMONKEY_RUNTIME: WORKER PASS shared_atomics=1");
