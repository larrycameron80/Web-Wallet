// let bip32 = require('bip32')
// let bip39 = require('bip39')
// let secp256k1 = require('secp256k1')
// let CryptoJS = require('crypto-js')
const utils = require('./tools/index')
const spendCrypto = require("./spend-crypto")

let tx = require("./tx.json")
const seed = "forward coconut salmon illegal now random select suit seminar click recall hen rhythm improve oven core utility rain enable energy fish lounge follow such"

let getWalletFromSeed = spendCrypto.getWalletFromSeed
let wallet = getWalletFromSeed(seed)
let signWithPrivateKey =  spendCrypto.signWithPrivateKey
const recursiveSortJson = utils.abcSortJson

// function log(object) {
//   console.log(util.inspect(object, false, null, true))
// }

window.utils = utils;
window.spendCrypto = spendCrypto;

// return;



tx = tx.value
tx["chain_id"] = "spend";
tx["account_number"] = "0";
tx["sequence"] = "6";
tx["msgs"] = tx["msg"];
delete (tx.msg)

console.log(tx, tx.msgs[0].value)
tx = recursiveSortJson(tx);



console.log( "tx tuka e dobro" )
console.log( tx)
privateKey = wallet.keys.private.buffer;
signature = signWithPrivateKey(tx, privateKey).signature.toString("base64");
console.log(signature)

