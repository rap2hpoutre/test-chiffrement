const _sodium = require("libsodium-wrappers");

function generateRandomString(length) {
  let result = "";
  for (let i = 0; i < length; i++) {
    // Generating a Unicode code point between 0x0000 and 0xFFFF
    const randomCodePoint = Math.floor(Math.random() * 0xffff);
    result += String.fromCharCode(randomCodePoint);
  }
  return result;
}

console.log("build big string (100 MB) please wait...");
const text = new Array(100000).fill(generateRandomString(1024)).join("");

(async () => {
  await _sodium.ready;
  const sodium = _sodium;

  function initKeyFromString(passphrase) {
    const targetKeyBytes =
      sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES;

    const hashed = sodium.crypto_generichash(
      sodium.crypto_generichash_BYTES,
      sodium.from_string(passphrase)
    );

    if (hashed.length === targetKeyBytes) {
      return hashed;
    }

    const key = new Uint8Array(targetKeyBytes);

    if (hashed.length < targetKeyBytes) {
      // If hashed is smaller than target key size, we pad it with zeros
      key.set(hashed);
    } else {
      // If hashed is larger than target key size, we truncate it
      key.set(hashed.subarray(0, targetKeyBytes));
    }

    return key;
  }

  function encryptStringWithKey(plainText, key) {
    const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    const header = stream.header;
    const cipherText = sodium.crypto_secretstream_xchacha20poly1305_push(
      stream.state,
      sodium.from_string(plainText),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    );

    return {
      header: header,
      cipherText: cipherText,
    };
  }

  function decryptWithKey(encryptedData, key) {
    const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
      encryptedData.header,
      key
    );
    const decrypted = sodium.crypto_secretstream_xchacha20poly1305_pull(
      state,
      encryptedData.cipherText,
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    );

    if (!decrypted) {
      throw new Error("Failed to decrypt or authentication tag mismatch");
    }

    return sodium.to_string(decrypted.message);
  }

  function getMemoryUsage() {
    const used = process.memoryUsage().heapUsed / 1024 / 1024;
    return `${Math.round(used * 100) / 100} MB`;
  }

  console.log("Memory before init:", getMemoryUsage());
  console.time("init");
  const key = initKeyFromString("mano");
  console.timeEnd("init");
  console.log("Memory after init:", getMemoryUsage());
  console.log("--------------------");
  console.log("Memory before encrypt:", getMemoryUsage());
  console.time("encrypt");
  const encryptedData = encryptStringWithKey(text, key);
  console.timeEnd("encrypt");
  console.log("Memory after encrypt:", getMemoryUsage());
  console.log("encrypted length", encryptedData.cipherText.length);
  console.log("--------------------");
  console.log("Memory before decrypt:", getMemoryUsage());
  console.time("decrypt");
  const decryptedString = decryptWithKey(encryptedData, key);
  console.timeEnd("decrypt");
  console.log("Memory after decrypt:", getMemoryUsage());
  console.log("decrypted length", decryptedString.length);
  console.log("--------------------");

  console.log("done");
  console.log(decryptedString.substring(0, 20));
  console.log("--------------------");

  delete encryptedData;
  delete text;

  // Wait for the garbage collector to free the memory
  setTimeout(() => {
    console.log("Memory after and garbage collection:", getMemoryUsage());
  }, 10000);
})();
