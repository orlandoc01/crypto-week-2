//@flow weak
const _ = require('lodash/fp');
const L = require('lodash');
const crypto = require('crypto');

const BLOCK_SIZE_BYTES = 16;
const ZERO_IV = Buffer.alloc(BLOCK_SIZE_BYTES);

const makeHexBlocks = _.flow(_.split(''), _.chunk(BLOCK_SIZE_BYTES * 2), _.map(_.join('')));

const aesBlockCipherDecrypt = (cipher, key) => {
  const decipherManual = crypto.createDecipheriv('aes-128-cbc', Buffer.from(key, 'hex'), ZERO_IV);
  decipherManual.setAutoPadding(false);
  const messagePart1 = decipherManual.update(Buffer.from(cipher, 'hex'));
  const messagePart2 = decipherManual.final();
  return Buffer.concat([messagePart1, messagePart2]).toString('hex');
}

const aesBlockCipherEncrypt = (message, key) => {
  const cipherManual = crypto.createCipheriv('aes-128-cbc', Buffer.from(key, 'hex'), ZERO_IV);
  cipherManual.setAutoPadding(false);
  const messagePart1 = cipherManual.update(Buffer.from(message, 'hex'));
  const messagePart2 = cipherManual.final();
  return Buffer.concat([messagePart1, messagePart2]).toString('hex');
}

const xorHex = (a, b) => {
  const maxLength = Math.min(a.length, b.length);
  const aChars = a.split('').slice(0, maxLength);
  const bChars = b.split('').slice(0, maxLength);
  const joinByXor = _.zipWith((a,b) => (parseInt(a, 16) ^ parseInt(b, 16)).toString(16));
  return joinByXor(aChars, bChars).join('');
}

const addMax256ToHex = (hex, num) => {
  const lastByte = hex.slice(hex.length - 2);
  const newLastValue = (parseInt(lastByte, 16) + num).toString(16);
  const newLastByte = L.padStart(newLastValue, 2, '0');
  return `${hex.slice(0, hex.length - 2)}${newLastByte}`;
};

module.exports = {
  xorHex,
  makeHexBlocks,
  addMax256ToHex,
  aesBlockCipherDecrypt,
  aesBlockCipherEncrypt
}
