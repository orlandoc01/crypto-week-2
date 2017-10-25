//@flow
const crypto = require('crypto');
const decryptAESwCBC = require('./manual-decryption.js');
const assert = require('assert');

console.log("Testing AES-128-CBC Decryption Script");
run_aes_decrypt_test1();

//Built In Decryption;
function run_aes_decrypt_test1() {
  const aes_cbc_key1 = '140b41b22a29beb4061bda66b6747e14';
  const aes_cbc_cipher1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81';

  //Implemented message
  const iv = Buffer.from(aes_cbc_cipher1.slice(0, 32), 'hex');
  const cipher = Buffer.from(aes_cbc_cipher1.slice(32), 'hex');
  const key = Buffer.from(aes_cbc_key1, 'hex');
  const decryptor = crypto.createDecipheriv('aes128', key, iv);
  const message1 = decryptor.update(cipher);
  const message2 = decryptor.final();
  const messageHex = Buffer.concat([message1, message2]).toString('hex');

  //Manual message;
  const manualMessageHex = decryptAESwCBC(aes_cbc_cipher1, aes_cbc_key1);

  //Test
  assert.strictEqual(messageHex, manualMessageHex);
  console.log("Testing AES-128-CBC Decryption Passed!");
}



