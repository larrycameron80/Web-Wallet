// let bip32 = require('bip32')
// let bip39 = require('bip39')
// let secp256k1 = require('secp256k1')
// let CryptoJS = require('crypto-js')

window.utils = require('./tools/index');

window.spendCrypto = require("./spend-crypto");



let getWalletFromSeed = spendCrypto.getWalletFromSeed
let wallet = getWalletFromSeed(seed)
let signWithPrivateKey =  spendCrypto.signWithPrivateKey
const recursiveSortJson = utils.abcSortJson

function log(object) {
  console.log(util.inspect(object, false, null, true))
}

return;

let tx = require("./tx.json")
const seed = "forward coconut salmon illegal now random select suit seminar click recall hen rhythm improve oven core utility rain enable energy fish lounge follow such"


tx = tx.value
tx["chain_id"] = "spend";
tx["account_number"] = "0";
tx["sequence"] = "6";
tx["msgs"] = tx["msg"];
delete (tx.msg)

console.log(tx, tx.msgs[0].value)
tx = recursiveSortJson(tx);





privateKey = wallet.keys.private.buffer;
signature = signWithPrivateKey(tx, privateKey).signature.toString("base64");
console.log(signature)


