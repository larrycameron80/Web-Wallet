let bip32 = require('bip32')
let bip39 = require('bip39')
let secp256k1 = require('secp256k1')
let CryptoJS = require('crypto-js')
const utils = require('../tools/index')

let config = require("../config.json")

const hdPathAtom = config.hdPathAtom

// converts a string to a bech32 version of that string which shows a type and has a checksum
const bech32ify = utils.bech32ify

// gets adress & keys from mnemonic
function getWalletFromSeed(mnemonic) {
    const masterKey = deriveMasterKey(mnemonic)
    const keys = deriveKeypair(masterKey)
    const address = getAddress(keys.publicKey.hex)
    console.log(keys, address)
    return {
        keys,
        address

    }
}

//produces the signature for a message (returns Buffer)
function signWithPrivateKey(signMessage, privateKey) {
    const signMessageString =
        typeof signMessage === 'string' ? signMessage : "" + JSON.stringify(signMessage)
    const signHash = Buffer.from(CryptoJS.SHA256(signMessageString).toString(), `hex`)
    

    // console.log(signHash)
    // const auuu = secp256k1.sign(signHash, privateKey)
    const signature = secp256k1.sign(signHash, privateKey)
    // const { signature } = secp256k1.sign(signHash, privateKey)
    return signature
}

// derives adress from publicKey
function getAddress(publicKeyHex) {
    const message = CryptoJS.enc.Hex.parse(publicKeyHex)
    const message256 = CryptoJS.SHA256(message);
    const hex = CryptoJS.RIPEMD160(message256).toString()
    const buffer = Buffer.from(hex, "hex");
    const prefix = 'spend'
    const bech32 = bech32ify(hex, prefix)

    return {
        buffer,
        bech32,
        hex
    }
}

// derives masterKey from mnemonic
function deriveMasterKey(mnemonic) {
    // throws if mnemonic is invalid
    bip39.validateMnemonic(mnemonic)
    const seed = bip39.mnemonicToSeedSync(mnemonic)
    const masterKey = bip32.fromSeed(seed)

    return masterKey
}
// derives masterkey to privateKey and publicKey keys
function deriveKeypair(masterKey) {
    const cosmosHD = masterKey.derivePath(hdPathAtom)
    const privateKey = {};
    const publicKey = {};
    privateKey.buffer = cosmosHD.privateKey;
    privateKey.hex = cosmosHD.privateKey.toString("hex")
    publicKey.buffer = secp256k1.publicKeyCreate(privateKey.buffer, true)
    publicKey.base64 = publicKey.buffer.toString("base64")
    publicKey.hex = publicKey.buffer.toString("hex")
    publicKey.secp256k1prefix = "EB5AE98721".toLowerCase();
    publicKey.bech32 = bech32ify(publicKey.secp256k1prefix + publicKey.hex, "spendpub");

    return {
        privateKey,
        publicKey
    }
}

function getAddressFromPrivateKey(privateHex){
    const pubKey = secp256k1.publicKeyCreate(Buffer.from(privateHex , `hex`), true)
    const publicKey = pubKey.toString("base64")
    const address = getAddress(pubKey.toString("hex")).bech32.string

    return {publicKey , address}
}

function generateMnemonic() {
    return bip39.generateMnemonic(256)
}

function bufferFromHex(hexString){
    return Buffer.from(hexString , `hex`)
}

module.exports = {
    bufferFromHex,
    getWalletFromSeed,
    signWithPrivateKey,
    getAddressFromPrivateKey,
    generateMnemonic
}