let spendCrypto = require("./crypto")



module.exports = {
    bufferFromHex: spendCrypto.bufferFromHex,
    getWalletFromSeed: spendCrypto.getWalletFromSeed,
    signWithPrivateKey: spendCrypto.signWithPrivateKey,
    generateMnemonic: spendCrypto.generateMnemonic ,
    getAddressFromPrivateKey: spendCrypto.getAddressFromPrivateKey
}