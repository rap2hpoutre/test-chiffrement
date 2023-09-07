const libsodium = require("libsodium-wrappers");
const { Buffer } = require("buffer");

function btoa(str) {
  return Buffer.from(str, "binary").toString("base64");
}

// atob equivalent in Node.js
function atob(base64Encoded) {
  return Buffer.from(base64Encoded, "base64").toString("binary");
}

function generateRandomString(length) {
  let result = "";
  for (let i = 0; i < length; i++) {
    // Generating a Unicode code point between 0x0000 and 0xFFFF
    const randomCodePoint = Math.floor(Math.random() * 0xffff);
    result += String.fromCharCode(randomCodePoint);
  }
  return result;
}

console.log("build 200k strings of 1kb please wait...");
const texts = new Array(200000).fill(generateRandomString(1024));
console.log(texts.reduce((a, b) => a + b.length, 0));

/*

Utils

*/
const _appendBuffer = function (buffer1, buffer2) {
  const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return new Uint8Array(tmp.buffer);
};
/*

Master key

*/

const derivedMasterKey = async (password) => {
  await libsodium.ready;
  const sodium = libsodium;
  const targetKeyBytes = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES;

  const hashed = sodium.crypto_generichash(
    sodium.crypto_generichash_BYTES,
    sodium.from_string(password)
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

  // Uint8Array
  return key;
};
/*

Decrypt

*/

const _decrypt_after_extracting_nonce = async (
  nonce_and_ciphertext_b64,
  key_uint8array
) => {
  await libsodium.ready;
  const sodium = libsodium;

  const nonce_and_cypher_uint8array = sodium.from_base64(
    nonce_and_ciphertext_b64,
    sodium.base64_variants.ORIGINAL
  );

  if (
    nonce_and_cypher_uint8array.length <
    sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES
  ) {
    throw new Error("Short message");
  }

  const nonce_uint8array = nonce_and_cypher_uint8array.slice(
    0,
    sodium.crypto_secretbox_NONCEBYTES
  );
  const ciphertext_uint8array = nonce_and_cypher_uint8array.slice(
    sodium.crypto_secretbox_NONCEBYTES
  );
  return sodium.crypto_secretbox_open_easy(
    ciphertext_uint8array,
    nonce_uint8array,
    key_uint8array
  );
};

const _decrypt_after_extracting_nonce_uint8array = async (
  nonce_and_cypher_uint8array,
  key_uint8array
) => {
  await libsodium.ready;
  const sodium = libsodium;

  if (
    nonce_and_cypher_uint8array.length <
    sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES
  ) {
    throw new Error("Short message");
  }

  const nonce_uint8array = nonce_and_cypher_uint8array.slice(
    0,
    sodium.crypto_secretbox_NONCEBYTES
  );
  const ciphertext_uint8array = nonce_and_cypher_uint8array.slice(
    sodium.crypto_secretbox_NONCEBYTES
  );
  return sodium.crypto_secretbox_open_easy(
    ciphertext_uint8array,
    nonce_uint8array,
    key_uint8array
  );
};

const decrypt = async (encryptedContent, encryptedEntityKey, masterKey) => {
  const entityKey_bytes_array = await _decrypt_after_extracting_nonce(
    encryptedEntityKey,
    masterKey
  );
  const content_uint8array = await _decrypt_after_extracting_nonce(
    encryptedContent,
    entityKey_bytes_array
  );
  const content = atob(new TextDecoder().decode(content_uint8array));

  return {
    content,
    entityKey: entityKey_bytes_array,
  };
};

/*

Encrypt

*/
const generateEntityKey = async () => {
  await libsodium.ready;
  const sodium = libsodium;
  return sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
};

const _encrypt_and_prepend_nonce = async (
  message_string_or_uint8array,
  key_uint8array
) => {
  await libsodium.ready;
  const sodium = libsodium;

  let nonce_uint8array = sodium.randombytes_buf(
    sodium.crypto_secretbox_NONCEBYTES
  );
  const crypto_secretbox_easy_uint8array = sodium.crypto_secretbox_easy(
    message_string_or_uint8array,
    nonce_uint8array,
    key_uint8array
  );
  const arrayBites = _appendBuffer(
    nonce_uint8array,
    crypto_secretbox_easy_uint8array
  );
  return sodium.to_base64(arrayBites, sodium.base64_variants.ORIGINAL);
};

const _encrypt_and_prepend_nonce_uint8array = async (
  message_string_or_uint8array,
  key_uint8array
) => {
  await libsodium.ready;
  const sodium = libsodium;

  let nonce_uint8array = sodium.randombytes_buf(
    sodium.crypto_secretbox_NONCEBYTES
  );
  const crypto_secretbox_easy_uint8array = sodium.crypto_secretbox_easy(
    message_string_or_uint8array,
    nonce_uint8array,
    key_uint8array
  );
  const arrayBites = _appendBuffer(
    nonce_uint8array,
    crypto_secretbox_easy_uint8array
  );
  return arrayBites;
};

const encodeContent = (content) => {
  try {
    const purifiedContent = content
      // https://stackoverflow.com/a/31652607/5225096
      .replace(
        /[\u007F-\uFFFF]/g,
        (chr) => "\\u" + ("0000" + chr.charCodeAt(0).toString(16)).substr(-4)
      )
      .replace(/\//g, "\\/");
    const base64PurifiedContent = btoa(purifiedContent);
    return base64PurifiedContent;
  } catch (errorPurifying) {
    console.log("error purifying content", errorPurifying);
    throw errorPurifying;
  }
};

const encrypt = async (content, entityKey, masterKey) => {
  const encryptedContent = await _encrypt_and_prepend_nonce(
    encodeContent(content),
    entityKey
  );
  const encryptedEntityKey = await _encrypt_and_prepend_nonce(
    entityKey,
    masterKey
  );

  return {
    encryptedContent: encryptedContent,
    encryptedEntityKey: encryptedEntityKey,
  };
};

(async () => {
  const encryptItem = async (item, hashedOrgEncryptionKey) => {
    const entityKey = await generateEntityKey();
    const { encryptedContent, encryptedEntityKey } = await encrypt(
      item,
      entityKey,
      hashedOrgEncryptionKey
    );

    return { encryptedContent, encryptedEntityKey };
  };

  function getMemoryUsage() {
    const used = process.memoryUsage().heapUsed / 1024 / 1024;
    return `${Math.round(used * 100) / 100} MB`;
  }

  console.log("Memory before init:", getMemoryUsage());
  console.time("init");
  const key = await derivedMasterKey("mano");
  console.timeEnd("init");
  console.log("Memory after init:", getMemoryUsage());
  console.log("--------------------");
  console.log("Memory before encrypt:", getMemoryUsage());
  console.time("encrypt");
  const encryptedData = [];
  for (let i = 0; i < texts.length; i++) {
    const tmp = await encryptItem(texts[i], key);
    encryptedData.push(tmp);
  }
  console.timeEnd("encrypt");
  console.log("Memory after encrypt:", getMemoryUsage());
  console.log(
    "encrypted length",
    encryptedData.reduce((a, b) => a + b.encryptedContent.length, 0) /
      1024 /
      1024
  );
  console.log("--------------------");
  console.log("Memory before decrypt:", getMemoryUsage());
  console.time("decrypt");
  const decryptedData = [];
  for (let i = 0; i < encryptedData.length; i++) {
    const tmp = await decrypt(
      encryptedData[i].encryptedContent,
      encryptedData[i].encryptedEntityKey,
      key
    );
    decryptedData.push(tmp.content);
  }
  console.timeEnd("decrypt");
  console.log("Memory after decrypt:", getMemoryUsage());
  console.log(
    "decrypted length",
    decryptedData.reduce((a, b) => a + b.length, 0)
  );
  console.log("--------------------");

  console.log("done");
  console.log(texts[0].substring(0, 20));
  console.log(decryptedData[0].substring(0, 20));
  console.log("--------------------");

  // Wait for the garbage collector to free the memory
  setTimeout(() => {
    console.log("Memory after and garbage collection:", getMemoryUsage());
  }, 10000);
})();
