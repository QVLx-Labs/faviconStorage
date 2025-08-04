faviconStorage
--------------
Not accessible via DevTools
No standard storage interface (localStorage, sessionStorage, IndexedDB) shows it — attackers can’t casually inspect or extract contents.
Non-extractable AES-GCM encryption
The encryption key never leaves memory.
Marked extractable: false, meaning the raw key bytes can’t be stolen — only used internally.
Even live XSS attacks cannot extract the key.
No persistence = No leftovers
Everything is ephemeral — gone on page reload or close.
No risk of leftover keys or data in browser storage between sessions.
Opaque channel (steganography)
Data hidden in favicon alpha channel using a custom VM.
Completely invisible to browser storage APIs or common fingerprinting tools.
Only your own bytecode can access or modify the data.
No one can extract anything without reverse-engineering the interpreter and executing controlled payloads.
If storage is used, effectively busts the cache.

You may also want to see these related explorations:
  https://github.com/STashakkori/MalwareDetection/tree/main/FaviconBeacon
  https://github.com/STashakkori/Favicon-Stegostealth
  https://github.com/STashakkori/Remediations/blob/main/favicon-restore.js
  https://github.com/STashakkori/Utilities/blob/main/generatePNG.html

Enjoy.

Passes tests:
Running faviconStorage tests...
vm-rt:20 [1] setItem() → demoKey = hello world. Going to keep writing. Why not????
vm-rt:24 [2] getItem() → demoKey
vm-rt:27 Length: 47
vm-rt:28 Raw chars: Array(47)
vm-rt:32 Expected chars: Array(47)
vm-rt:33 Exact match? true
vm-rt:34 ✅ GET result: hello world. Going to keep writing. Why not????
vm-rt:37 [3] removeItem() → demoKey
vm-rt:41 [4] getItem() after remove → demoKey
vm-rt:47 Value is null
vm-rt:49 Exact match? true
vm-rt:50 ✅ GET after delete: null
vm-rt:54 [5] setItem() encrypted value → secretKey = You found easter egg #0: Hello, Samy Kamkar!
vm-rt:58 [6] getItem() decrypted value
vm-rt:61 Length: 44
vm-rt:62 Raw chars: Array(44)
vm-rt:66 Expected chars: Array(44)
vm-rt:67 Exact match? true
vm-rt:68 ✅ Decrypted value: You found easter egg #0: Hello, Samy Kamkar!
vm-rt:71 [7] clear()
vm-rt:74 ✅ All tests passed.
favicon-storage.js:242 [FaviconRestorer] Favicon restored.
