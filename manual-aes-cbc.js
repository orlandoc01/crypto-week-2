//@flow weak
const _ = require('lodash/fp');
const L = require('lodash');
const { 
  makeHexBlocks, 
  aesBlockCipherEncrypt, 
  aesBlockCipherDecrypt, 
  xorHex 
} = require('./util.js');
const BLOCK_SIZE_BYTES = 16;

module.exports = {
  decryptAESwCBC,
  encryptAESwCBC
}

function decryptAESwCBC(cipherHex, keyHex) {
  const [iv, ...cipherHexBlocks] = makeHexBlocks(cipherHex);
  const rawMessage = cipherHexBlocks.reduce((chunks, block, index) => {
    const prev = index === 0 ? iv : cipherHexBlocks[index - 1];
    const xoredMessage = aesBlockCipherDecrypt(block, keyHex);
    const rawMessage = xorHex(xoredMessage, prev);
    return `${chunks}${rawMessage}`;
  }, '');
  const paddingLength = parseInt(rawMessage.slice(rawMessage.length - 2), 16);
  return rawMessage.slice(0, rawMessage.length - paddingLength * 2);
}

function encryptAESwCBC(messageHex, keyHex, ivHex) {
  const rawHexBlocks = makeHexBlocks(messageHex);
  const lastBlock = _.last(rawHexBlocks);
  const paddingSize = (BLOCK_SIZE_BYTES - lastBlock.length / 2);
  const paddingByte = L.padStart(paddingSize.toString(16), 2, '0');
  const padding = _.repeat(paddingSize, paddingByte);
  const addBlock = paddingSize === '0';
  const messageHexBlocks = addBlock ? [...rawHexBlocks, padding] : [..._.initial(rawHexBlocks), `${lastBlock}${padding}`];
  const cipherHexBlocks = messageHexBlocks.reduce((chunks, block, index) => {
    const prev = index === 0 ? ivHex : chunks[index - 1];
    const xorMessage = xorHex(prev, block);
    return [...chunks, aesBlockCipherEncrypt(xorMessage, keyHex)];
  }, []);
  return `${ivHex}${cipherHexBlocks.join('')}`;
}

