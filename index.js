//@flow
const crypto = require('crypto');
const util = require('./util.js');
const CBC = require('./manual-aes-cbc.js');
const CTR = require('./manual-aes-ctr.js');
const assert = require('assert');

run_aes_cbc_test();
run_aes_ctr_test();

function run_aes_cbc_test() {
  console.log("Testing AES-128-CBC Script");
  const aes_cbc_key1 = '140b41b22a29beb4061bda66b6747e14';
  const aes_cbc_cipher1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81';

  const iv_hex = aes_cbc_cipher1.slice(0, 32);
  const iv = Buffer.from(iv_hex, 'hex');
  const cipher = Buffer.from(aes_cbc_cipher1.slice(32), 'hex');
  const key = Buffer.from(aes_cbc_key1, 'hex');

  //Implemented message
  const decryptor = crypto.createDecipheriv('aes-128-cbc', key, iv);
  const message1 = decryptor.update(cipher);
  const message2 = decryptor.final();
  const messageHex = Buffer.concat([message1, message2]).toString('hex');

  //Manual message;
  const manualMessageHex = CBC.decryptAESwCBC(aes_cbc_cipher1, aes_cbc_key1);
  //Manual cipher
  const manualCipherHex = CBC.encryptAESwCBC(messageHex, aes_cbc_key1, iv_hex);

  //Test
  assert.strictEqual(messageHex, manualMessageHex);
  console.log("Testing AES-128-CBC Decryption Passed!");
  assert.strictEqual(aes_cbc_cipher1, manualCipherHex);
  console.log("Testing AES-128-CBC Encryption Passed!");
}

function run_aes_ctr_test() {
  console.log("Testing AES-128-CTR Script");
  const aes_ctr_key1 = '36f18357be4dbd77f050515c73fcf9f2';
  const aes_ctr_cipher1 = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329';

  const iv_hex = aes_ctr_cipher1.slice(0, 32);
  const iv = Buffer.from(iv_hex, 'hex');
  const cipher = Buffer.from(aes_ctr_cipher1.slice(32), 'hex');
  const key = Buffer.from(aes_ctr_key1, 'hex');

  //Implemented message
  const decryptor = crypto.createDecipheriv('aes-128-ctr', key, iv);
  const message1 = decryptor.update(cipher);
  const message2 = decryptor.final();
  const messageHex = Buffer.concat([message1, message2]).toString('hex');

  //Manual message;
  const manualMessageHex = CTR.decryptAESwCTR(aes_ctr_cipher1, aes_ctr_key1);
  //Manual cipher
  const manualCipherHex = CTR.encryptAESwCTR(messageHex, aes_ctr_key1, iv_hex);

  //Test
  // console.log("RESULUTS");
  // console.log(util.makeHexBlocks(messageHex));
  // console.log(util.makeHexBlocks(manualMessageHex));
  assert.strictEqual(messageHex, manualMessageHex);
  console.log("Testing AES-128-CTR Decryption Passed!");
  assert.strictEqual(aes_ctr_cipher1, manualCipherHex);
  console.log("Testing AES-128-CTR Encryption Passed!");
}



