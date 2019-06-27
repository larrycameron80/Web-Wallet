let bech32 = require('bech32')

// Sorts Json object or anb array of objects A - Z order
function recursiveSortJson(json) {
    if (json instanceof Array) {
        var sorted = []
        var array = json.sort()
        for (key in array) {
            if (typeof array[key] == "string") {
                sorted.push(array[key])
            }
            if (typeof array[key] == "number") {
                sorted.push(array[key])
            }
            if (typeof array[key] == "object") {
                sorted.push(recursiveSortJson(array[key]))
            }
        }
        return sorted;
    } else {
        var sorted = {}
        var jsonKeys = Object.keys(json);
        jsonKeys = jsonKeys.sort()

        for (key of jsonKeys) {
            if (typeof json[key] == "string") {
                sorted[key] = json[key]
            } else if (typeof json[key] == "number") {
                sorted[key] = json[key].toString()
            } else if (typeof json[key] == "object") {
                if (json[key] != null) {
                    sorted[key] = recursiveSortJson(json[key]);
                }
            }
        }
    }
    return sorted;
}

// converts a string to a bech32 version of that string which shows a type and has a checksum
function bech32ify(address, prefix) {
    const words = bech32.toWords(Buffer.from(address, 'hex'))
    return {
        string: bech32.encode(prefix, words),
        words,
        prefix
    }
}


module.exports = {
    abcSortJson: recursiveSortJson,
    bech32ify: bech32ify
}

