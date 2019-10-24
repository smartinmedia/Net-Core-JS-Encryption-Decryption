/*
 * How this works:
 * password: the password to hash as a string
 * options (optional): objects in the form:
 *  
 * {
 *      "Salt": string, // Can be empty. If you provide, it must be in Hex!!
 *      "Cost": int, //(the "N" of scrypt, default is 16384)
 *      "BlockSize": int, // (the "r", default is 8)
 *      "Parallel": int, // (the "p", default is 1)
 *      "KeySizeInBytes": int // (default is 32)
 * }
 *
 *
 * callback must be of form: callback(error, progress, key)
 * error and progress can be null, key must be there to fill it with resulting key string
 */

function scryptHandler() {

    var that = this;

    this.Hash = function(password, options, callback) {
        var asyncFunc = true;
        if (callback == null) {
            asyncFunc = false;
        }
        if (options == null) {
            options = {
                "Salt": CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(32)), //(can be empty or null, then string is automatically created)
                "Cost": 16384, //(the "N" of scrypt, default is 16384)
                "BlockSize": 8, // (the "r", default is 8)
                "Parallel": 1, // (the "p", default is 1)
                "KeySizeInBytes": 32 // (default is 32)
            }
        }

        // if one of the options exist, but others not
        ('Salt' in options) || (options.Salt = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(32)));
        ('Cost' in options) || (options.Cost = 16384);
        ('BlockSize' in options) || (options.BlockSize = 8);
        ('Parallel' in options) || (options.Parallel = 1);
        ('KeySizeInBytes' in options) || (options.KeySizeInBytes = 32);

        var passwordBuffer = new buffer.SlowBuffer(password.normalize('NFKC'), 'utf8');
        var saltBuffer = new buffer.SlowBuffer(options.Salt, 'hex');
        
        if (!asyncFunc) {
            var synchKey = scrypt(passwordBuffer,
                saltBuffer,
                options.Cost,
                options.BlockSize,
                options.Parallel,
                options.KeySizeInBytes,
                asyncFunc);

            synchKey = new buffer.SlowBuffer(synchKey);

            var keyString = "scrypt2:" +
                options.Cost.toString() +
                ":" +
                options.BlockSize.toString() +
                ":" +
                options.Parallel.toString() +
                ":" +
                + "0" //to mimic C# "maxThreads = null - here, a "0" is correct
                + ":"
                + options.KeySizeInBytes
                + ":"
                + saltBuffer.toString('hex')
                + ":"
                + synchKey.toString('hex');
            return keyString;

        } else {
            scrypt(passwordBuffer,
                saltBuffer,
                options.Cost,
                options.BlockSize,
                options.Parallel,
                options.KeySizeInBytes,
                asyncFunc,
                function (error, progress, key) {

                    if (error) {
                        callback(error);
                        //outputText += "Cancelled: " + parseInt(100 * progress) + "% done";

                    } else if (key) {
                        key = new buffer.SlowBuffer(key);

                        var keyString = "scrypt2:" +
                            options.Cost.toString() +
                            ":" +
                            options.BlockSize.toString() +
                            ":" +
                            options.Parallel.toString() +
                            ":" +
                            + "0" //to mimic C# "maxThreads = null - here, a "0" is correct
                            + ":"
                            + options.KeySizeInBytes
                            + ":"
                            + saltBuffer.toString('hex')
                            + ":"
                            + key.toString('hex');

                        callback(null, 1.0, keyString);


                    }

                    else if(progress || key) {
                        // update UI with progress complete
                        callback(null, progress, null);
                    }


                });
        }

        

    }

    this.comparePasswordWithHash = function(password, hashString, callback2) {
        var asyncFunc = true;
        if (callback2 == null) {
            asyncFunc = false;
        }
        var parts = hashString.split(":");
        if (parts.size < 8) {
            if (asyncFunc) {
                callback2("This is not a valid hash string");
            }
            
            return false;
        }
        if (parts[0] != "scrypt2") {
            if (asyncFunc) {
                callback2("This is not a valid hash string");

            }
            return false;
        }
        var cost = parseInt(parts[1]);
        var blockSize = parseInt(parts[2]);
        var parallel = parseInt(parts[3]);
        var keySizeInBytes = parseInt(parts[5]);
        var salt = parts[6];
        //var salt = decodeURIComponent(parts[6].replace(/\s+/g, '').replace(/[0-9a-f]{2}/g, '%$&'));

        if (!asyncFunc) {
            var syncKey = that.Hash(password,
                {
                    "Salt": salt,
                    "Cost": cost,
                    "BlockSize": blockSize,
                    "Parallel": parallel,
                    "KeySizeInBytes": keySizeInBytes
                });
            if (syncKey == hashString) {
                return true;
            } else {
                return false;
            }

        } else {
            that.Hash(password,
                {
                    "Salt": salt,
                    "Cost": cost,
                    "BlockSize": blockSize,
                    "Parallel": parallel,
                    "KeySizeInBytes": KeySizeInBytes
                },
                function (error, progress, key) {
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

    this.GetOnlyHashInHexString = function (password, cO) {

        var options = {
            "Salt": cO["Salt"], //(can be empty or null, then string is automatically created)
            "Cost": cO["Cost"], //(the "N" of scrypt, default is 16384)
            "BlockSize": cO["BlockSize"], // (the "r", default is 8)
            "Parallel": cO["Parallel"], // (the "p", default is 1)
            "KeySizeInBytes": cO["KeySizeInBytes"] // (default is 32)
        }
        var hash = that.Hash(password, options);
        var parts = hash.split(":");
        return parts[7];
    }

}

