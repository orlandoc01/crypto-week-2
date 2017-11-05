//@flow weak
const _ = require('lodash/fp');
const L = require('lodash');
const { 
  xorHex,
  makeHexBlocks, 
  addMax256ToHex,
  aesBlockCipherEncrypt, 
} = require('./util.js');

module.exports = {
  decryptAESwCTR,
  encryptAESwCTR
}

function decryptAESwCTR(cipherHex, keyHex) {
  const [ivHex, ...cipherHexBlocks] = makeHexBlocks(cipherHex);
  return cipherHexBlocks.reduce((prev, block, index) => {
    const seed = addMax256ToHex(ivHex, index);
    const xorKey = aesBlockCipherEncrypt(seed, keyHex);
    const messageBlock = xorHex(xorKey, block);
    return `${prev}${messageBlock}`;
  }, "");
}

function encryptAESwCTR(messageHex, keyHex, ivHex) {
  const messageHexBlocks = makeHexBlocks(messageHex);
  const rawCipher =  messageHexBlocks.reduce((prev, block, index) => {
    const seed = addMax256ToHex(ivHex, index);
    const xorKey = aesBlockCipherEncrypt(seed, keyHex);
    const messageBlock = xorHex(xorKey, block);
    return `${prev}${messageBlock}`;
  }, "");
  return `${ivHex}${rawCipher}`;
}
