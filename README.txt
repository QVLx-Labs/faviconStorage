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
Custom VM interpreter
Only your own bytecode can access or modify the data.
No one can extract anything without reverse-engineering the interpreter and executing controlled payloads.

Enjoy.

Passes tests:
Running faviconStorage tests...
vm-rt:20 [1] setItem() → demoKey = hello world. Going to keep writing. Why not????
vm-rt:24 [2] getItem() → demoKey
vm-rt:27 Length: 47
vm-rt:28 Raw chars: (47) [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 46, 32, 71, 111, 105, 110, 103, 32, 116, 111, 32, 107, 101, 101, 112, 32, 119, 114, 105, 116, 105, 110, 103, 46, 32, 87, 104, 121, 32, 110, 111, 116, 63, 63, 63, 63]
vm-rt:32 Expected chars: (47) [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 46, 32, 71, 111, 105, 110, 103, 32, 116, 111, 32, 107, 101, 101, 112, 32, 119, 114, 105, 116, 105, 110, 103, 46, 32, 87, 104, 121, 32, 110, 111, 116, 63, 63, 63, 63]
vm-rt:33 Exact match? true
vm-rt:34 ✅ GET result: hello world. Going to keep writing. Why not????
vm-rt:37 [3] removeItem() → demoKey
vm-rt:41 [4] getItem() after remove → demoKey
vm-rt:47 Value is null
vm-rt:49 Exact match? true
vm-rt:50 ✅ GET after delete: null
vm-rt:54 [5] setItem() encrypted value → secretKey = !!!!!SensitiveDataWith!!!!!!!UTF8
vm-rt:58 [6] getItem() decrypted value
vm-rt:61 Length: 33
vm-rt:62 Raw chars: (33) [33, 33, 33, 33, 33, 83, 101, 110, 115, 105, 116, 105, 118, 101, 68, 97, 116, 97, 87, 105, 116, 104, 33, 33, 33, 33, 33, 33, 33, 85, 84, 70, 56]
vm-rt:66 Expected chars: (33) [33, 33, 33, 33, 33, 83, 101, 110, 115, 105, 116, 105, 118, 101, 68, 97, 116, 97, 87, 105, 116, 104, 33, 33, 33, 33, 33, 33, 33, 85, 84, 70, 56]
vm-rt:67 Exact match? true
vm-rt:68 ✅ Decrypted value: !!!!!SensitiveDataWith!!!!!!!UTF8
vm-rt:71 [7] clear()
vm-rt:74 ✅ All tests passed.
favicon-storage.js:242 [FaviconRestorer] Favicon restored.
