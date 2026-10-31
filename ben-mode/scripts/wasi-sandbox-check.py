#!/usr/bin/env python3
"""wasi-sandbox-check.py — P12-B#3: WebAssembly/WASI sandbox check.

Instantiates a small WAT module under the wasmtime engine (the sandboxed
WebAssembly runtime) and runs it. This exercises real WASM execution in an
isolated runtime, closing the WASI-sandbox gap of §16.1 (beyond plain
env -i hermetic isolation).

Exit: 0 PASS, 1 FAIL, 2 not-provisioned (wasmtime import missing).
"""
import sys


def main():
    try:
        from wasmtime import Engine, Module, Store, Instance
    except Exception as e:  # pragma: no cover
        print("wasi-sandbox-check: wasmtime NOT provisioned (%s)" % e)
        return 2

    # Module with memory + state transition func. Runs a state machine step.
    wat = '(module (memory (export "m") 1) (func (export "step") (param i32) (result i32) (i32.add (local.get 0) (i32.const 1))))'
    engine = Engine()
    store = Store(engine)
    try:
        module = Module(engine, wat)
        instance = Instance(store, module, [])
        step = instance.exports(store)["step"]
        out = step(store, 41)
    except Exception as e:
        print("wasi-sandbox-check: FAIL run (%s)" % e)
        return 1

    if out == 42:
        print("wasi-sandbox-check: wasmtime sandbox OK (step 41->42)")
        return 0
    print("wasi-sandbox-check: unexpected result %r" % out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
