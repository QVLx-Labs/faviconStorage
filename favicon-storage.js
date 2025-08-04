/*
  favicon-storage.js — Secure Public API for Favicon VM Storage

  Provides:
    faviconStorage.setItem(key, value)
    faviconStorage.getItem(key) → Promise<string|null>
    faviconStorage.removeItem(key)
    faviconStorage.clear()

  Uses AES-GCM encryption with a randomly generated, non-extractable CryptoKey per page load.

  $t@$h, QVLx Labs
*/

(() => {
  // Generate a fresh, non-extractable AES-GCM 256-bit key per page session.
  // This key cannot be exported or read by JS, but can be used by crypto.subtle encrypt/decrypt.
  let cryptoKeyPromise = crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,  // Non-extractable: prevents raw key export
    ["encrypt", "decrypt"]
  );

  // Utility: Convert Uint8Array to Base64 string
  function toBase64(u8) {
    let binary = '';
    for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i]);
    return btoa(binary);
  }

  // Utility: Convert Base64 string to Uint8Array
  function fromBase64(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const u8 = new Uint8Array(len);
    for (let i = 0; i < len; i++) u8[i] = binary.charCodeAt(i);
    return u8;
  }

  // Encrypt plaintext string → base64 encoded ciphertext
  async function encrypt(text) {
    const key = await cryptoKeyPromise;
    const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM IV (12 bytes)
    const data = new TextEncoder().encode(text); // Encode string as Uint8Array
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    const payload = new Uint8Array(iv.length + ct.byteLength);
    payload.set(iv);
    payload.set(new Uint8Array(ct), iv.length);
    return toBase64(payload);
  }

  // Decrypt base64 encoded ciphertext → plaintext string
  async function decrypt(b64) {
    const raw = fromBase64(b64);
    const iv = raw.slice(0, 12);
    const ct = raw.slice(12);
    const key = await cryptoKeyPromise;
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
  }

  // Compiles VM source code instructions into bytecode array
  function compileFaviconProgram(src) {
    const bytecode = [];
    const labels = {};
    const jumpFixups = [];
    const encode = s => new TextEncoder().encode(s);
    let position = 0;
    let ticks = 0;

    // Split source into lines and parse instructions
    const lines = src.trim().split("\n");
    for (let rawLine of lines) {
      const line = rawLine.split("//")[0].trim(); // Remove comments
      if (!line) continue;

      if (++ticks > 10000) throw new Error("Too many instructions");

      const parts = line.split(/\s+/);
      const instr = parts[0].toUpperCase();
      const emit = (...bytes) => { for (const b of bytes) bytecode.push(b), position++; };

      switch (instr) {
        case "STOREFAV": {
          const key = encode(parts[1]);
          const val = encode(parts.slice(2).join(" "));
          emit(0x20, key.length, ...key, val.length, ...val);
          break;
        }
        case "LOADFAV": {
          const key = encode(parts[1]);
          const target = parts[2] ? encode(parts[2]) : [];
          emit(0x21, key.length, ...key);
          if (target.length > 0) emit(target.length, ...target);
          break;
        }
        case "DELFAV": {
          const key = encode(parts[1]);
          emit(0x22, key.length, ...key);
          break;
        }
        default:
          throw new Error("Unknown or unsupported instruction: " + instr);
      }
    }

    // Patch forward-referenced jump addresses
    for (const fix of jumpFixups) {
      if (!(fix.label in labels)) throw new Error("Undefined label: " + fix.label);
      const addr = labels[fix.label];
      bytecode[fix.at] = (addr >> 8) & 0xff;
      bytecode[fix.at + 1] = addr & 0xff;
    }

    return new Uint8Array(bytecode);
  }

  // VM runtime to load bytecode and manipulate internal key-value store
  function createFaviconVM() {
    const internalStore = new Map();

    return Object.freeze({
      load(bytecode) {
        let ip = 0;

        // Helper to decode a length-prefixed string from bytecode
        const decodeStr = () => {
          const len = bytecode[ip++];
          const str = new TextDecoder().decode(bytecode.slice(ip, ip + len));
          ip += len;
          return str;
        };

        // Execute instructions until end of bytecode
        while (ip < bytecode.length) {
          const opcode = bytecode[ip++];

          switch (opcode) {
            case 0x20: { // STOREFAV: store encrypted value under key
              const kLen = bytecode[ip++];
              const key = new TextDecoder().decode(bytecode.slice(ip, ip + kLen));
              ip += kLen;

              const vLen = bytecode[ip++];
              const value = new TextDecoder().decode(bytecode.slice(ip, ip + vLen));
              ip += vLen;

              internalStore.set(key, value);
              break;
            }
            case 0x21: { // LOADFAV: retrieve encrypted value for key
              const kLen = bytecode[ip++];
              const key = new TextDecoder().decode(bytecode.slice(ip, ip + kLen));
              ip += kLen;

              const value = internalStore.get(key) ?? null;

              // Resolve the pending promise for "get" with found value
              if (typeof window.faviconStorage?._resolveLoad === "function") {
                window.faviconStorage._resolveLoad(value);
              }
              break;
            }
            case 0x22: { // DELFAV: delete stored value by key
              const kLen = bytecode[ip++];
              const key = new TextDecoder().decode(bytecode.slice(ip, ip + kLen));
              ip += kLen;

              internalStore.delete(key);
              break;
            }
            default:
              console.warn("[VM] Unknown opcode:", opcode);
              return;
          }
        }
      }
    });
  }

  const VM = createFaviconVM();

  // Restores golden favicon by fetching /favicon.png and injecting it
  const FaviconRestorer = (() => {
    // Fetch image from URL bypassing cache
    const fetchImage = async (url) => {
      try {
        const res = await fetch(url, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const blob = await res.blob();
        if (!blob.type.startsWith("image")) throw new Error("Not an image");

        return await new Promise((resolve, reject) => {
          const img = new Image();
          img.crossOrigin = "anonymous";
          img.onload = () => resolve(img);
          img.onerror = reject;
          img.src = URL.createObjectURL(blob);
        });
      } catch (e) {
        console.warn("[FaviconRestorer] Failed to fetch image:", url);
        return null;
      }
    };

    // Replace current favicon links with a new one from canvas blob
    const updateFavicon = (canvas) => {
      if (!canvas || !canvas.width || !canvas.height) return;

      canvas.toBlob(blob => {
        if (!blob) return;
        const blobURL = URL.createObjectURL(blob);

        // Remove all existing favicon link elements
        document.querySelectorAll("link[rel*='icon']").forEach(e => e.remove());

        // Insert new favicon link element
        const link = document.createElement("link");
        link.rel = "icon";
        link.type = "image/png";
        link.href = blobURL;
        document.head.appendChild(link);

        // Ensure Safari mask-icon override link exists
        let mask = document.querySelector('link[rel="mask-icon"]');
        if (!mask) {
          mask = document.createElement("link");
          mask.rel = "mask-icon";
          document.head.appendChild(mask);
        }
        mask.href = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>";

        // Ensure meta theme-color exists and is set
        let theme = document.querySelector('meta[name="theme-color"]');
        if (!theme) {
          theme = document.createElement("meta");
          theme.name = "theme-color";
          document.head.appendChild(theme);
        }
        theme.content = "#000000";

        console.log("[FaviconRestorer] Favicon restored.");
      }, "image/png");
    };

    // Fetch /favicon.png, draw to canvas, and update favicon
    const restore = async () => {
      const img = await fetchImage("/favicon.png");
      if (!img) return;

      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);
      updateFavicon(canvas);
    };

    return { restore };
  })();

  // Command dispatch queue
  const queue = [];
  let executing = false;
  let pendingResolve = null;

  // Queue commands for sequential execution
  function sendCommand(op, ...args) {
    queue.push({ op, args });
    executeNext();
  }

  // Execute next queued command
  async function executeNext() {
    if (executing || queue.length === 0) return;
    executing = true;

    const { op, args } = queue.shift();

    switch (op) {
      case "set": {
        const [key, value] = args;
        try {
          // Encrypt value, encode key and encrypted value as bytes
          const encrypted = await encrypt(value); // Base64 string
          const encodedKey = new TextEncoder().encode(key);
          const encodedEncrypted = new TextEncoder().encode(encrypted);

          // Build VM bytecode to store encrypted value under key
          const bytecode = new Uint8Array([
            0x20, // STOREFAV opcode
            encodedKey.length,
            ...encodedKey,
            encodedEncrypted.length,
            ...encodedEncrypted
          ]);
          VM.load(bytecode);
        } catch (e) {
          console.warn("[FaviconStorage] setItem() encryption error:", e);
        }
        break;
      }
      case "get": {
        const [key, resolver] = args;
        try {
          const encodedKey = new TextEncoder().encode(key);
          // Build VM bytecode to load encrypted value by key
          const bytecode = new Uint8Array([
            0x21, // LOADFAV opcode
            encodedKey.length,
            ...encodedKey
          ]);
          // Setup resolver for async decrypt and resolve of the value
          pendingResolve = async (encValue) => {
            try {
              const plain = await decrypt(encValue);
              resolver(plain);
            } catch {
              resolver(null);
            }
            pendingResolve = null;
          };
          VM.load(bytecode);
        } catch (e) {
          console.warn("[FaviconStorage] get() error:", e);
          resolver(null);
        }
        break;
      }
      case "delete": {
        const [key] = args;
        try {
          const encodedKey = new TextEncoder().encode(key);
          // Build VM bytecode to delete value by key
          const bytecode = new Uint8Array([
            0x22, // DELFAV opcode
            encodedKey.length,
            ...encodedKey
          ]);
          VM.load(bytecode);
        } catch (e) {
          console.warn("[FaviconStorage] delete() error:", e);
        }
        break;
      }
      case "clear": {
        try {
          // Clear storage by restoring the golden favicon image
          await FaviconRestorer.restore();
        } catch (e) {
          console.warn("[FaviconStorage] clear() failed:", e);
        }
        break;
      }
    }

    executing = false;
    executeNext();
  }

  const api = { // Public exposure
    setItem(key, value) {
      sendCommand("set", key, value);
    },
    getItem(key) {
      return new Promise(resolve => {
        sendCommand("get", key, resolve);
      });
    },
    removeItem(key) {
      sendCommand("delete", key);
    },
    clear() {
      sendCommand("clear");
    },
    _resolveLoad(value) {
      if (pendingResolve) {
        const r = pendingResolve;
        pendingResolve = null;
        r(value);
      }
    }
  };

  // Freeze API to prevent modification
  const frozenAPI = Object.freeze({
    setItem: api.setItem,
    getItem: api.getItem,
    removeItem: api.removeItem,
    clear: api.clear,
    _resolveLoad: api._resolveLoad
  });

  // Expose as non-writable, non-configurable global property
  Object.defineProperty(window, "faviconStorage", {
    value: frozenAPI,
    configurable: false,
    writable: false,
    enumerable: false
  });
})();
