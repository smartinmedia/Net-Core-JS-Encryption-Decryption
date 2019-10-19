/*
 * How this works:
 * password: the password to hash as a string
 * options (optional): objects in the form:
 * {
 *      "salt": string, //(can be empty or null, then string is automatically created)
 *      "cost": int, //(the "N" of scrypt, default is 16384)
 *      "blockSize": int, // (the "r", default is 8)
 *      "parallel": int, // (the "p", default is 1)
 *      "derivedKeyLength": int // (default is 32)
 * }
 *
 *
 * callback must be of form: callback(error, progress, key)
 * error and progress can be null, key must be there to fill it with resulting key string
 */

function scryptHandler() {

    var that = this;

    this.Hash = function(password, options, callback)
    {
        if (options == null) {
            options = {
                "salt": CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.random(32)), //(can be empty or null, then string is automatically created)
                "cost": 16384, //(the "N" of scrypt, default is 16384)
                "blockSize": 8, // (the "r", default is 8)
                "parallel": 1, // (the "p", default is 1)
                "derivedKeyLength": 32 // (default is 32)
            }
        }

        // if one of the options exist, but others not
        ('salt' in options) || (options.salt = CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.random(32)));
        ('cost' in options) || (options.cost = 16384);
        ('blockSize' in options) || (options.blockSize = 8);
        ('parallel' in options) || (options.parallel = 1);
        ('derivedKeyLength' in options) || (options.derivedKeyLength = 32);

        var passwordBuffer = new buffer.SlowBuffer(password.normalize('NFKC'), 'utf8');
        var saltBuffer = new buffer.SlowBuffer(options.salt.normalize('NFKC'), 'utf8');

        scrypt(passwordBuffer,
            saltBuffer,
            options.cost,
            options.blockSize,
            options.parallel,
            options.derivedKeyLength,
            function (error, progress, key) {

                if (error) {
                    callback(error);
                    //outputText += "Cancelled: " + parseInt(100 * progress) + "% done";

                } else if (key) {
                    key = new buffer.SlowBuffer(key);

                    var keyString = "scrypt2:" +
                        options.cost.toString() +
                        ":" +
                        options.blockSize.toString() +
                        ":" +
                        options.parallel.toString() +
                        ":" +
                        + "0" //to mimic C# "maxThreads = null - here, a "0" is correct
                        + ":"
                        + options.derivedKeyLength
                        + ":"
                        + saltBuffer.toString('hex')
                        + ":"
                        + key.toString('hex');

                    callback(null, 1.0, keyString);


                }

                else {
                    // update UI with progress complete
                    callback(null, progress, null);
                }


            });

    }

    this.comparePasswordWithHash = function(password, hashString, callback2) {
        var parts = hashString.split(":");
        if (parts.size < 8) {
            callback2(false);
            return;
        }
        if (parts[0] != "scrypt2") {
            callback2(false);
            return;
        }
        var cost = parseInt(parts[1]);
        var blockSize = parseInt(parts[2]);
        var parallel = parseInt(parts[3]);
        var derivedKeyLength = parseInt(parts[5]);
        var salt = decodeURIComponent(parts[6].replace(/\s+/g, '').replace(/[0-9a-f]{2}/g, '%$&'));

        that.Hash(password,
            {
                "salt": salt,
                "cost": cost,
                "blockSize": blockSize,
                "parallel": parallel,
                "derivedKeyLength": derivedKeyLength
            },
            function(error, progress, key) {
                if (key) {
                    if (key == hashString) {
                        callback2(true);
                    } else {
                        callback2(false);
                    }
                }
            });
    }
}

