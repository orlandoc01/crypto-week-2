//@flow
const crypto = require('crypto');
const _ = require('lodash/fp');

const BLOCK_SIZE_BYTES = 16;
const KEY_SIZE_BYTES = 16;
const ZERO_IV = Buffer.alloc(BLOCK_SIZE_BYTES);

module.exports = decryptAESwCBC;

function decryptAESwCBC(cipherHex: string, keyHex: string): string {
  const makeHexBlocks = _.flow(_.split(''), _.chunk(BLOCK_SIZE_BYTES * 2), _.join(''));
  const [iv, ...cipherHexBlocks] = makeHexBlocks(cipherHex);
  const ivPrime = aesBlockCipherEncrypt(iv, keyHex);
  const message = cipherHexBlocks.reduce((chunks, block, index) => {
    const prev = index === 0 ? ivPrime : cipherHexBlocks[index - 1];
    const xoredMessage = aesBlockCipherDecrypt(block, keyHex);
    const message = xorHex(xoredMessage, prev);
    return `${chunks}${message}`;
  }, '');
  return message;
}

function aesBlockCipherDecrypt(cipher: string, key: string) {
  const decipherManual = crypto.createDecipheriv('aes128', Buffer.from(key, 'hex'), ZERO_IV);
  const message1 = decipherManual.update(Buffer.from(cipher, 'hex'));
  const message2 = decipherManual.final();
  return Buffer.concat([message1, message2]).toString('hex');
}

function aesBlockCipherEncrypt(message: string, key: string) {
  const cipherManual = crypto.createCipheriv('aes128', Buffer.from(key, 'hex'), ZERO_IV);
  const message1 = cipherManual.update(Buffer.from(message, 'hex'));
  const message2 = cipherManual.final();
  return Buffer.concat([message1, message2]).toString('hex');
}

function xorHex(a: string, b: string): string {
  return (parseInt(a, 16) ^ parseInt(b, 16)).toString(16);
}

