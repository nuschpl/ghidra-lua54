# Lua 5.4 bytecode processor + loader for Ghidra

A standalone Ghidra extension that disassembles and (partially) decompiles **Lua 5.4
precompiled bytecode** — the output of `luac` / `string.dump`, i.e. the `lundump`
chunk format.

* **Target:** chunks produced by the **Lua 5.4.x** interpreter. The opcode set and
  instruction encoding were taken verbatim from the **Lua 5.4.7** reference source
  (`lopcodes.h`, `lundump.c`, `ldump.c`, `lvm.c`). The same bytecode format (version
  byte `0x54`) is used by every 5.4.x release (5.4.0 … 5.4.8), so 5.4.7 chunks are a
  subset of what this handles.
* **Header recognised:** signature `1B 4C 75 61` (`"\x1bLua"`) + version byte `0x54`
  + format `0x00` + `LUAC_DATA = 19 93 0D 0A 1A 0A`, with
  `sizeof(Instruction)=4`, `sizeof(lua_Integer)=8`, `sizeof(lua_Number)=8`,
  `LUAC_INT=0x5678`, `LUAC_NUM=370.5`.
* **Not supported:** other Lua versions (5.1/5.2/5.3 use a different version byte and a
  different instruction layout — they are explicitly rejected), and chunks compiled with
  non-default `lua_Integer`/`lua_Number` sizes (e.g. 32-bit builds). See *Limitations*.

This extension is self-contained: the SLEIGH processor **and** the loader live in one
module. It adds no existing-processor or loader modifications, and **no third-party
runtime dependencies** (see *Supply chain & provenance*).

> Built and verified against **Ghidra 12.2** (the first public release carrying the
> `Loader.ImporterSettings` API this loader uses) and Ghidra 12.3-DEV.

## Install (quickstart)

1. Download the extension zip from this repo's **Releases** (or build it — see *Building*).
   The zip is named `ghidra_<version>_PUBLIC_<date>_ghidra-lua54.zip`; its Ghidra version
   must match your Ghidra install.
2. In Ghidra: **File ▸ Install Extensions**, click the green **+**, select the zip, then
   restart Ghidra.
3. **File ▸ Import File…** a `.luac`; Ghidra auto-selects the *Lua 5.4 bytecode (luac)*
   loader. Analyze with the defaults.

---

## What you get

* A SLEIGH language **`Lua:LE:32:default`** that disassembles **all 83 opcodes**
  (`OP_MOVE` … `OP_EXTRAARG`) with correct operand decoding and p-code.
* A loader **"Lua 5.4 bytecode (luac)"** that:
  * validates the 5.4 header and parses the full `lundump` chunk (recursively, every
    nested prototype);
  * lays each prototype's `code[]` contiguously into the `ram` space (4 bytes per
    instruction) so intra-function jumps resolve correctly;
  * creates an entry point + named function per prototype
    (`lua_main`, `lua_func_L<line>` from debug line info);
  * attaches a **plate comment** per function listing its source, line range, parameter
    count, upvalues, constants, and locals;
  * attaches **EOL comments** resolving every constant / upvalue / nested-closure
    reference at its use site (e.g. `K[0] = "print"  U[0] = _ENV`).

---

## The Lua 5.4 instruction model

Each instruction is a 32-bit little-endian word:

```
 31      24 23      16 15 14       7 6         0
+----------+----------+--+----------+-----------+
|   C (8)  |   B (8)  |k |   A (8)  |  Op (7)   |   iABC
+----------+----------+--+----------+-----------+
|         Bx (17)        |   A (8)  |  Op (7)   |   iABx / iAsBx
+------------------------+----------+-----------+
|              Ax (25)              |  Op (7)   |   iAx
|              sJ (25)              |  Op (7)   |   isJ
+-----------------------------------+-----------+
```

Signed arguments use **excess-K** (not two's-complement):
`sBx = Bx - 65535`, `sJ = sJraw - 16777215`, `sB = B - 127`, `sC = C - 127`.
These are decoded at disassembly time (SLEIGH's `signed` keyword cannot express excess-K),
which is why immediates such as `ADDI r2,r0,-0x1` render correctly.

**Registers.** The Lua register window `R[0..255]` is modelled as an addressable
register space, 8 bytes per slot (a Lua value payload is a 64-bit integer or a 64-bit
double); `R[n]` lives at register offset `n*8` and prints as `rN`.

**Constants / upvalues / prototypes** are *per-prototype* pools, so a lone instruction
cannot name the enclosing function's `K[]`/`U[]`/`P[]`. They are therefore referenced by
*index* through CALLOTHER p-code ops (`luaLoadK`, `luaGetUpval`, `luaClosure`, …), and the
loader annotates each site with the resolved value. Disassembly shows `K[3]`, `U[0]`,
`P[1]`.

---

## Opcode coverage

All 83 opcodes **disassemble** with full operand decoding. The p-code column describes
semantic fidelity:

* **precise** – p-code matches the Lua VM for the normal (numeric/boolean) case.
* **int** – modelled with integer p-code (`INT_ADD`, `INT_AND`, …): exact when the
  operands are integers, approximate for floats (Lua values are dynamically typed and the
  static type is unknown). Bitwise ops are always integer in Lua, so those are exact.
* **cmp** – signed-integer comparison + conditional skip of the following `JMP` (correct
  control flow; exact for integer operands).
* **flow** – branch/loop control-flow edges are modelled precisely; the loop
  counter / condition itself is produced by a CALLOTHER.
* **opaque** – a CALLOTHER p-code op (table access, calls, closures, metamethods, varargs,
  concat, …): correct as an uninterpreted effect, but the decompiler cannot see through it.

| # | Opcode | Disasm | P-code | Notes |
|---|--------|:------:|:------:|-------|
| 0 | MOVE | ✅ | precise | `rA = rB` |
| 1 | LOADI | ✅ | precise | `rA = sBx` |
| 2 | LOADF | ✅ | precise | `rA = (double)sBx` (`int2float`) |
| 3 | LOADK | ✅ | opaque | `luaLoadK(K[Bx])`; value in EOL comment |
| 4 | LOADKX | ✅ | opaque | index in following EXTRAARG |
| 5 | LOADFALSE | ✅ | precise | `rA = 0` |
| 6 | LFALSESKIP | ✅ | precise+flow | `rA = 0; pc++` |
| 7 | LOADTRUE | ✅ | precise | `rA = 1` |
| 8 | LOADNIL | ✅ | opaque | sets `rA..rA+B`; `rA=0` + `luaLoadNil` |
| 9 | GETUPVAL | ✅ | opaque | name in EOL comment |
| 10 | SETUPVAL | ✅ | opaque | |
| 11 | GETTABUP | ✅ | opaque | `U[B][K[C]]`; both resolved in comment |
| 12 | GETTABLE | ✅ | opaque | |
| 13 | GETI | ✅ | opaque | integer key |
| 14 | GETFIELD | ✅ | opaque | `R[B][K[C]]` |
| 15 | SETTABUP | ✅ | opaque | RK(C) via k bit |
| 16 | SETTABLE | ✅ | opaque | RK(C) |
| 17 | SETI | ✅ | opaque | RK(C) |
| 18 | SETFIELD | ✅ | opaque | RK(C) |
| 19 | NEWTABLE | ✅ | opaque | `rA = luaNewTable(B,C)` |
| 20 | SELF | ✅ | opaque | `rA+1 = rB; rA = rB[RK(C)]` |
| 21 | ADDI | ✅ | int | `rA = rB + sC` |
| 22–24 | ADDK/SUBK/MULK | ✅ | int | `rB op K[C]` |
| 25 | MODK | ✅ | opaque | Lua floor-modulo (`luaMod`) |
| 26 | POWK | ✅ | opaque | float pow (`luaPow`) |
| 27 | DIVK | ✅ | opaque | float div (`luaDiv`) |
| 28 | IDIVK | ✅ | opaque | floor div (`luaIDiv`) |
| 29–31 | BANDK/BORK/BXORK | ✅ | int (exact) | integer bitwise |
| 32 | SHRI | ✅ | opaque | Lua shift semantics (`luaShr`) |
| 33 | SHLI | ✅ | opaque | `sC << rB` (`luaShl`) |
| 34–36 | ADD/SUB/MUL | ✅ | int | register–register |
| 37 | MOD | ✅ | opaque | `luaMod` |
| 38 | POW | ✅ | opaque | `luaPow` |
| 39 | DIV | ✅ | opaque | `luaDiv` |
| 40 | IDIV | ✅ | opaque | `luaIDiv` |
| 41–43 | BAND/BOR/BXOR | ✅ | int (exact) | |
| 44–45 | SHL/SHR | ✅ | opaque | `luaShl`/`luaShr` |
| 46 | MMBIN | ✅ | opaque | metamethod fixup after arithmetic |
| 47 | MMBINI | ✅ | opaque | |
| 48 | MMBINK | ✅ | opaque | |
| 49 | UNM | ✅ | int | `rA = -rB` |
| 50 | BNOT | ✅ | int (exact) | `rA = ~rB` |
| 51 | NOT | ✅ | precise | `rA = (rB == 0)` |
| 52 | LEN | ✅ | opaque | `#rB` (`luaLen`) |
| 53 | CONCAT | ✅ | opaque | `luaConcat` |
| 54 | CLOSE | ✅ | opaque | |
| 55 | TBC | ✅ | opaque | to-be-closed mark |
| 56 | JMP | ✅ | flow | `goto` (sJ, instruction-relative) |
| 57–59 | EQ/LT/LE | ✅ | cmp | skip following JMP on `(cond != k)` |
| 60 | EQK | ✅ | cmp | vs `K[B]` |
| 61–65 | EQI/LTI/LEI/GTI/GEI | ✅ | cmp | vs signed immediate |
| 66 | TEST | ✅ | cmp | truthiness test |
| 67 | TESTSET | ✅ | cmp+precise | `rA = rB` on fall-through |
| 68 | CALL | ✅ | opaque+flow | `luaCall(rA,B,C)` |
| 69 | TAILCALL | ✅ | opaque+ret | `luaTailCall` then `return` |
| 70 | RETURN | ✅ | opaque+ret | `luaReturn` then `return` |
| 71 | RETURN0 | ✅ | ret | `return` |
| 72 | RETURN1 | ✅ | ret | `r0 = rA; return` |
| 73 | FORLOOP | ✅ | flow | back edge `pc -= Bx`; `luaForLoop` |
| 74 | FORPREP | ✅ | flow | forward exit `pc += Bx+1`; `luaForPrep` |
| 75 | TFORPREP | ✅ | flow | unconditional `pc += Bx` |
| 76 | TFORCALL | ✅ | opaque | `luaTForCall` |
| 77 | TFORLOOP | ✅ | flow | back edge; `luaTForLoop` |
| 78 | SETLIST | ✅ | opaque | `luaSetList` |
| 79 | CLOSURE | ✅ | opaque | `rA = luaClosure(P[Bx])`; target in comment |
| 80 | VARARG | ✅ | opaque | `luaVararg` |
| 81 | VARARGPREP | ✅ | opaque | |
| 82 | EXTRAARG | ✅ | opaque | continuation of the previous opcode |

---

## Building

You need a Ghidra installation to build against. Point `GHIDRA_INSTALL_DIR` at it; use
JDK 25 and Gradle 9.1 (what Ghidra 12.x requires). From the repo root:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/lua54.slaspec   # compile the .sla
gradle buildExtension -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"    # package the zip
```

This produces the installable extension under `dist/`:
`dist/ghidra_<version>_PUBLIC_<date>_ghidra-lua54.zip`.

Notes:
* `buildExtension` does **not** compile SLEIGH, so run the `sleigh` step first; the
  resulting `lua54.sla` is then bundled into the zip (kept next to its `.slaspec`/`.sinc`,
  which Ghidra checks for source consistency).
* The loader Java is compiled against the Ghidra install's API — see *Version compatibility*.

### Continuous integration

`.github/workflows/release.yml` builds the **one** source tree against **one or more**
Ghidra versions and, on a pushed `v*` tag, attaches **every** produced zip to a single
GitHub Release — one zip per Ghidra version (there is no single cross-version zip; see
*Version compatibility*). Two build jobs:

* **`build-public`** — GitHub-hosted; downloads the pinned public release
  (`GHIDRA_TAG` = `Ghidra_12.2_build`) and **verifies its SHA-256 before building**
  (`GHIDRA_SHA256` is required — a tag alone is not a pin). Produces the zip for external
  public-release users.
* **`build-ours`** — opt-in; runs only when the repo variable `GHIDRA_INSTALL_DIR` points
  at a trusted, self-built Ghidra on a self-hosted runner (labels from `RUNNER_LABELS`).
  **No download**; the build is hermetic (`buildExtension --offline`, no third-party
  dependencies). Produces the zip for that build.

Both jobs build identical source; each zip is stamped with its build Ghidra's version.
Enable `build-ours` by setting the two repo variables — no code change.

> **The Ghidra you build against sets the extension's compatibility.** The zip is stamped
> with that Ghidra's `application.version` and installs only into a Ghidra reporting the
> same version string (the `PUBLIC`/`DEV` release name is not compared). A `12.2` zip
> therefore installs into both the public 12.2 release and a from-source 12.2 build.

---

## Installing

**From a release (recommended):** download the `*_ghidra-lua54.zip` for your Ghidra
version, then **File ▸ Install Extensions ▸ green +**, select the zip, and restart Ghidra.

**From a local build:** same dialog, pointed at the `dist/…zip` produced by *Building*.

The extension zip's Ghidra version (in its name) must match your Ghidra install; Ghidra
refuses extensions built for a different version.

---

## Importing a `.luac`

1. **File ▸ Import File…** and choose your `.luac`.
2. Ghidra auto-selects the **"Lua 5.4 bytecode (luac)"** loader and the
   **`Lua:LE:32:default`** language. Import, then **Analyze** with the defaults.
3. Each prototype appears as a function (`lua_main`, `lua_func_L<line>`); constant and
   upvalue references are annotated in-line.

Headless:

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless <proj_dir> <proj_name> \
    -import your.luac -deleteProject
```

The loader is auto-detected from the header — **do not** pass `-loader "Lua 5.4 bytecode (luac)"`:
the headless `-loader` *name* option is validated before the class search finishes and will
report "Invalid loader name". Use plain `-import` (auto-detect), or constrain with
`-processor "Lua:LE:32:default"` if you want to be explicit. The GUI importer lists the
loader by name normally.

---

## Verification status (evidence)

Verified against a copy of the local **Ghidra 12.3-DEV** install (the authoring tree's
version), using two fixtures compiled from `.lua` with `luac` 5.4.x
(`data/tests/factorial.luac`, `data/tests/strings_tables.luac`):

* **SLEIGH:** compiles with no errors/warnings (`sleigh`, both 12.3 and the standalone
  compiler).
* **Loader:** header parsed; **3** functions created for `factorial.luac`
  (`lua_main`, `lua_func_L5`, `lua_func_L13`), **2** for `strings_tables.luac`
  (`lua_main`, `lua_func_L8`) — names match the source line numbers.
* **Disassembly:** 47 and 37 instructions respectively, matching `luac -l` output
  opcode-for-opcode and operand-for-operand; jump/loop targets match `luac`'s own labels
  (e.g. `FORPREP r3,0x1004c` / `FORLOOP r3,0x10020`), signed immediates decode correctly
  (`ADDI r2,r0,-0x1`), and constants/upvalues resolve in comments
  (`GETTABUP r3,U[0x0],K[0x0]  ; K[0] = "print"  U[0] = _ENV`).
* **P-code:** `LOADI→COPY`, `MOVE→COPY`, `ADD→INT_ADD`, comparisons→`CBRANCH`,
  `FORPREP/FORLOOP→CALLOTHER + INT_NOTEQUAL + CBRANCH`, calls→`CALLOTHER`.
* **Decompiler:** produces structured, readable output. For the recursive `fib` the
  decompiler recovered `if (param_1 < 2) return param_1;`, both recursive calls, and
  `return lVar1 + lVar2`; for `factorial` it recovered the `result = 1` / multiply-loop /
  `return result` structure.

---

## Limitations (be candid)

This is a **register-based VM** with dynamically-typed, tagged values. A decompiler that
assumes a C-like machine will necessarily produce approximate output. Honestly:

1. **Call results and for-loop induction variables are not tracked.** `CALL`, `FORLOOP`,
   `FORPREP`, `TFOR*`, `SETLIST`, `VARARG`, table access and metamethods are CALLOTHER ops,
   so the decompiler shows the call but cannot connect its result to the register it writes.
   Arithmetic on a call result (`fib(n-1) + fib(n-2)`) is therefore shown structurally but
   the operands may conflate the callee value with its return value.
2. **Arithmetic is modelled as integer.** `ADD/SUB/MUL/ADDI` and the `*K` variants emit
   `INT_*` p-code — exact for integer operands, approximate for floats. `MOD/POW/DIV/IDIV`
   and all shifts are opaque because their Lua semantics (floor division/modulo, float
   coercion, shift-by-negative) do not map to a single p-code op. Bitwise ops are exact.
3. **Comparisons are signed-integer.** Correct for integers; float/string comparisons are
   approximate.
4. **Constants/upvalues/prototypes are referenced by index, not value,** in p-code (they
   are per-prototype pools). Resolved values are provided as listing comments only, not as
   decompiler data. A future enhancement could implement a `ConstantPool`/`cpool`-based
   resolver (as the JVM/Dalvik modules do) so constants appear directly in the decompiler.
5. **The register window is a flat 8-byte-slot model.** `LOADNIL R[A..A+B]`,
   `CONCAT R[A..A+B-1]`, multi-value `CALL`/`RETURN`/`VARARG` ranges are summarised, not
   expanded per register.
6. **Metamethod (`MMBIN*`) fixups are shown as straight-line calls.** At runtime the
   preceding arithmetic op skips them on the fast path; that conditional skip is not
   modelled (it depends on runtime operand types), so they appear to execute
   unconditionally.
7. **Only the default 64-bit integer / 64-bit float build is supported.** Chunks from a
   Lua built with other `lua_Integer`/`lua_Number` sizes are rejected by the header check.

### Prioritised remaining work for better decompilation
1. Implement a `PcodeInjectLibrary` + `ConstantPool` so `LOADK`/`GETFIELD`/`GETTABUP`
   resolve constants into the decompiler (biggest readability win).
2. Model `CALL`/`RETURN` result registers (inject p-code that writes `R[A..A+C-2]`) so call
   results flow into subsequent instructions.
3. Model `FORLOOP`/`FORPREP` integer-loop counter updates in p-code (not CALLOTHER) so loop
   induction variables are recovered.
4. Split arithmetic into integer vs float paths using constant-type hints from the loader.

## Supply chain & provenance

This extension is deliberately dependency-light; everything it ships is accounted for:

* **No third-party runtime dependencies.** `build.gradle` declares an empty
  `dependencies` block. The extension bundles only its own compiled jar
  (`lib/ghidra-lua54.jar`) and runs purely on the Ghidra API. There is nothing to audit
  for transitive CVEs.
* **Build dependency.** Exactly one: a Ghidra installation (`GHIDRA_INSTALL_DIR`). The
  build against it is **hermetic** — `buildExtension` pulls no third-party dependencies
  (verified with `--offline`), so the only trusted input is the Ghidra install itself plus
  this repo's source. Preferred toolchain is a **trusted self-built Ghidra** (CI "ours"
  mode, no download). The temporary public-release path pins by **both** the release tag
  `Ghidra_12.2_build` **and** the SHA-256 of the zip, verified before building — a tag
  alone is not a pin. (A public release is a different artifact from an internal
  from-source build; don't conflate the two.)
* **Instruction/format model provenance.** The opcode set, encoding and chunk format were
  derived from the **Lua 5.4.7 reference source** (`lopcodes.h`, `lundump.c`, `ldump.c`,
  `lvm.c`, from lua.org). No third-party disassembler or bytecode library was copied or
  forked; this is clean-room work using Ghidra's own JVM/Dalvik modules as structural
  templates.
* **Test fixtures.** `data/tests/*.luac` are self-generated by compiling the adjacent
  `*.lua` sources (included) with **`luac` from Lua 5.4.8 (Homebrew)** — byte-format
  identical to 5.4.7 (version `0x54`, unchanged opcodes). Their provenance is fully in-repo
  and reproducible; they are not third-party binaries.
* **Shipped SLEIGH `.sla`.** Not committed; it is compiled from the in-repo
  `data/languages/lua54.slaspec`/`.sinc` by the Ghidra `sleigh` compiler of the
  `GHIDRA_INSTALL_DIR` used for the build (CI: the `Ghidra_12.2_build` release's `sleigh`),
  then bundled into the release zip.
* **Further pinning (recommended).** The CI references its GitHub Actions by major-version
  tag and the JDK/Gradle by exact version; for a fully pinned toolchain, additionally pin
  each Action by commit SHA and set `gradle-distribution-sha256-sum` on the Gradle setup.
* **Untrusted-input hardening.** A `.luac` is untrusted input. The parser bounds every
  element count and allocation against the input size, caps prototype nesting depth and
  the assembled code-image size, rejects out-of-range varints, and neutralizes Ghidra
  comment-annotation syntax in strings taken from the file.

## Version compatibility

* The **SLEIGH language and the chunk format are version-independent** — the `.sla`/`.ldefs`
  work in any reasonably recent Ghidra.
* The **loader Java** targets the Ghidra Loader API introduced by **Ghidra 12.2**
  (`AbstractProgramWrapperLoader.load(Program, Loader.ImporterSettings)`); it builds
  unchanged against 12.2 and 12.3-DEV. On an **older released Ghidra (11.x)** the Loader
  API is the six-argument
  `load(ByteProvider, LoadSpec, List<Option>, Program, TaskMonitor, MessageLog)`; port by
  changing that one method signature (and reading `provider`/`monitor` from the parameters
  instead of `settings`). Nothing else in the loader differs between the two APIs.
