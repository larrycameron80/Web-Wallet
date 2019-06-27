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
    const address = getAddress(keys.public.hex)

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
    prefix = `spend`
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
// derives masterkey to private and public keys
function deriveKeypair(masterKey) {
    const cosmosHD = masterKey.derivePath(hdPathAtom)
    const private = {};
    const public = {};
    private.buffer = cosmosHD.privateKey;
    private.hex = cosmosHD.privateKey.toString("hex")
    public.buffer = secp256k1.publicKeyCreate(private.buffer, true)
    public.base64 = public.buffer.toString("base64")
    public.hex = public.buffer.toString("hex")
    public.secp256k1prefix = "EB5AE98721".toLowerCase();
    public.bech32 = bech32ify(public.secp256k1prefix + public.hex, "spendpub");

    return {
        private,
        public
    }
}

module.exports = {
    getWalletFromSeed,
    signWithPrivateKey
}