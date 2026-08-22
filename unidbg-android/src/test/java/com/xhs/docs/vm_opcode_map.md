# libtiny.so VM Opcode Map

> Generated: 2026-04-06
> Binary: libtiny.so (SHA256: 0ee606cc...)
> Architecture: ARM64, handler-threaded VM

## 1. VM Architecture Overview

### 1.1 Core Design
- **Type**: Handler-threaded interpreter (NOT bytecode-based)
- **Total handlers**: 47,831
- **State register**: X19 (points to ~8KB VM context struct)
- **Dispatch**: Computed indirect jumps (BR X8/X9/X10)
- **Handler chaining**: Each handler computes next handler address and jumps directly

### 1.2 Dispatch Mechanism
```
; Central trampoline (vm_dispatch_17B44C):
MOV  X9, #0xFFFFFFFFFCEBDE40    ; = -0x31421C0
ADD  X8, X8, X9                  ; target = encoded - 0x31421C0
BR   X8                          ; jump to handler

; Handler address encoding:
encoded_value = handler_addr + 0x31421C0
handler_addr  = encoded_value - 0x31421C0

; Direct dispatch (most handlers):
; Uses global offset tables + computed offsets
; off_745B80, off_7453D0, off_73AD70, etc.
```

### 1.3 VM Register File (X19 + offset)
```
Offset Range    | Access Pattern | Purpose (inferred)
----------------|----------------|--------------------
0x0028-0x0098   | Heavy read     | Special: SP, PC, flags, context ptrs
0x03C0-0x0404   | Medium R/W     | Secondary register bank
0x0408-0x0488   | Heavy R/W      | Primary working registers (highest traffic)
0x1D20-0x1D50   | Occasional     | Pointer registers (used in map insert)
0x0DEB          | Occasional W   | Flag/condition register
```

### 1.4 VM Type System (sub_287A44 switch cases)
| Type ID | Name     | Description |
|---------|----------|-------------|
| 1       | Tree/Map | Red-black tree (key-value pairs) |
| 2       | Array    | Dynamic array (vector<variant>) |
| 3       | String   | SSO string (small string optimization) |
| 4       | Bytes    | Raw byte buffer |
| 5       | Int64    | 64-bit integer |
| 6       | Bool     | Boolean |
| 7       | Float    | Floating point (maybe) |
| 8       | Nested   | Nested map/object |

## 2. Opcode Categories

### 2.1 Summary Table
| Category    | Count  |    %  | Description |
|-------------|--------|-------|-------------|
| DISPATCH    | 17,945 | 37.5% | Pure dispatch / trampoline / goto |
| CMP_SELECT  |  9,627 | 20.1% | Compare + conditional select (CSEL) |
| VM_RW       |  5,752 | 12.0% | Read VM reg -> compute -> write VM reg |
| VM_LOAD     |  5,255 | 11.0% | Read from VM register (no write) |
| CMP_SET     |  3,190 |  6.7% | Compare + set flag (CSET) |
| VM_STORE    |  2,014 |  4.2% | Write to VM register (no read) |
| CALL        |  3,798 |  7.9% | Call native function via BLR |
| XOR         |    128 |  0.3% | Bitwise XOR operation |
| MUL         |    120 |  0.3% | Multiply / multiply-add |

### 2.2 Conditional Branch Points
- **Multi-target dispatchers**: 1,739 handlers
  - 2 targets: 535 (if/else)
  - 3 targets: 402 (if/elif/else or switch-3)
  - 4 targets: 326
  - 5 targets: 264
  - 6 targets: 212

### 2.3 Dispatch Register Usage
| Register | Count |    %  |
|----------|-------|-------|
| X10      | 1,018 | 33.9% |
| X9       |   847 | 28.2% |
| X8       |   806 | 26.9% |
| Others   |   330 | 11.0% |

## 3. Native Function Calls (CALL Handlers)

### 3.1 Top Native Targets
| Count | Function     | Semantic | Description |
|-------|-------------|----------|-------------|
| 1,864 | (unresolved) | various | IDA couldn't resolve BLR target |
| 190   | sub_1702D4  | **tree_traverse** | Red-black tree traversal/serialization (switch 8 types) |
| 163   | sub_28C7E8  | **map_insert** | Insert key-value into map (SSO string key) |
| 105   | sub_6F01C4  | **log_error** | vsnprintf "mod load failed: %s" |
| 86    | sub_16FA34  | **tree_free** | Recursive tree node free (left→right→node) |
| 64    | sub_44BF68  | **vector_push** | Vector push_back with reallocation |
| 47    | sub_16FA98  | **tree_free2** | Another tree cleanup variant |
| 41    | sub_40E758  | **jni_call** | Indirect call through off_75D1D0 (JNI?) |
| 26    | sub_287A44  | **variant_copy** | Deep copy variant type (switch 1-8) |
| 25    | sub_5F3A38  | **unknown** | TBD |
| 20    | sub_28B5EC  | **map_insert2** | Alternative map insert wrapper |
| 18    | sub_28A368  | **map_lookup** | Map key lookup |
| 18    | sub_44BDD4  | **map_insert3** | Yet another map insert variant |
| 16    | sub_287A44  | **variant_copy** | Deep copy variant (recursive) |
| 14    | sub_17004C  | **int_to_str** | Number→string (uses localeconv) |
| 12    | sub_29D30C  | **unknown** | TBD |
| 12    | sub_5771A8  | **unknown** | TBD |
| 10    | sub_3075D8  | **unknown** | TBD |
| 10    | sub_15BF1C  | **unknown** | TBD |
| 10    | sub_56D180  | **unknown** | TBD |
| 10    | sub_601040  | **unknown** | TBD |

### 3.2 Key Functions Detail

#### sub_28C7E8 (map_insert) - 163 call handlers
```c
// Takes: a1 = map pointer, a2 = C string key
// 1. Compute strlen(key)
// 2. Create SSO std::string from key
// 3. Call sub_286958 (red-black tree insert)
// 4. Free SSO if heap-allocated
// This is where ALL map keys are inserted (including x146 on real device)
```

#### sub_1702D4 (tree_traverse) - 190 call handlers
```c
// Takes: a1 = tree root, a2 = type tag
// Switch on type (1-8):
//   case 1: traverse tree children
//   case 2: copy vector
//   case 3: deep copy string
//   case 8: handle nested structure
// Used for serializing the fingerprint map to JSON
```

#### sub_287A44 (variant_copy) - 26 call handlers
```c
// Deep copy a variant value
// Switch on type byte at *a2:
//   1: tree (alloc node, copy children recursively)
//   2: array (alloc array, copy each element recursively)
//   3: string (SSO string copy)
//   5,6,7: primitive (int64/bool/float - direct copy)
//   8: nested map (alloc + copy)
```

## 4. Handler Naming Convention

All 47,829 VM handlers have been renamed in IDA with the pattern:
```
vm_{category}_{address}
```

Examples:
- `vm_call_28C7E8_1DCF38` — handler at 0x1DCF38 that calls sub_28C7E8
- `vm_cmp_sel_17E330` — compare + select handler at 0x17E330
- `vm_rw_1A3840` — read/write VM register handler
- `vm_dispatch_1DE6C8` — pure dispatch/goto handler

## 5. x146 Execution Path (from Frida backtrace)

```
0x191164  (entry)
    ↓
0x2780f4  (sub_2780AC: setup VM context, call sub_1F21D4)
    ↓
0x1f64a4  (VM dispatcher)
    ↓
0x1f212c  (VM dispatcher)
    ↓
0x1f1f44  (sub_1F1E60: alloc 496-byte VM state, init, lock mutex, call sub_17004C)
    ↓
0x1dcf68  (vm_call_28C7E8_1DCF38: ★ THE x146 map_insert handler ★)
    ↓
sub_28C7E8 → sub_286958 (actual RB-tree insert)
```

### x146 Handler Detail (vm_call_28C7E8_1DCF38)
```asm
; Load key string pointer from global table
LDR  X8, [off_746350]           ; base = 0xFFFFFFFFA2BB544C
LDR  X1, [X8, #0x5DBFD00C]     ; X1 = key "x146" C-string ptr
LDR  X0, [X19, #0x50]          ; X0 = map pointer from VM reg

; Call map_insert
BLR  computed_addr              ; → sub_28C7E8(map, "x146")

; Post-insert: swap/copy bytes (VM register shuffling)
LDRB W8, [X0]
STRB W8, [X19, #0x1D4D]        ; temp save
LDR  X8, [X19, #0x1D20]
STRB [X0], ...                  ; byte swap
STR  X0, [X19, #0x1D50]        ; advance pointer

; Dispatch to next handler (0x1DE6C8)
BR   X8                         ; → vm_dispatch_1DE6C8
```

**Key observation**: The x146 VALUE comes from the map pointer at `[X19+0x50]`.
The value is already computed and stored in the map entry before this handler runs.
To find where the value is computed, trace who writes to `[X19+0x50]` before this handler.

## 6. VM Register Usage Heatmap

```
Offset  Read   Write  Purpose (inferred)
------  -----  -----  ------------------
0x0488    521    647   Working reg R0 (highest write)
0x0480    510    635   Working reg R1
0x0470    505    629   Working reg R2
0x0460    506    618   Working reg R3
0x047C    486    605   Working reg R4
0x0450    503    600   Working reg R5
0x0448    503    592   Working reg R6
0x046C    482    579   Working reg R7
0x045C    479    576   Working reg R8
0x0440    486    516   Working reg R9
0x0438    477    514   Working reg R10
0x0418    468    504   Working reg R11
0x0410    453    499   Working reg R12
0x0408    453    496   Working reg R13
0x0430    465    488   Working reg R14
0x0428    458    486   Working reg R15
0x0444    450    486   Working reg R16
0x0424    424    475   Working reg R17
0x03F0    409    363   Secondary R0
0x03C0    406    372   Secondary R1
0x0098    377    160   Special: heavy read (context ptr?)
0x0028    374     84   Special: very heavy read (PC or SP?)
0x0050    282    111   ★ Map pointer (used by x146 insert)
0x005C    ...    ...   Used by CMP handlers (comparison operand)
```

## 7. Usage Guide

### Finding a specific key's handler
1. Search IDA for `vm_call_28C7E8` to find all map_insert handlers
2. Each one inserts a different key — check the global table offset to identify which key

### Tracing data flow through VM
1. Identify the VM register offset(s) involved
2. Search for handlers that write to that offset: `vm_rw_*`, `vm_store_*`
3. Follow the handler chain backwards

### Identifying conditional branches
1. Look for `vm_dispatch_*` handlers with IDA comments "调用多个地址:..."
2. These are the VM's if/switch statements
3. The number of targets indicates branch complexity

### Finding hash/crypto operations
1. Look for sequences of `vm_xor_*` and `vm_mul_*` handlers
2. These are likely hash/crypto primitives
3. Cross-reference with `vm_rw_*` handlers for state accumulation
