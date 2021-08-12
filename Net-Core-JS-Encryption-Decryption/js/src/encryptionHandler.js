function encryptionHandler() {



    /*

    Excellent JS descriptioN:
    https://dev.to/halan/4-ways-of-symmetric-cryptography-and-javascript-how-to-aes-with-javascript-3o1b

     PasswordDerivationOptions (options):
     {
        "DerivationType": "scrypt", // optionally: rfc
        "Salt": "3a069e9126af66a839067f8a272081136d8ce63ed72176dc8a29973d2b15361f", //SALT must be in Hex
        "Cost": 16384, //only for DerivationType "scrypt", not for "rfc"
        "BlockSize": 8, //only for DerivationType "scrypt", not for "rfc"
        "Parallel": 1, //only for DerivationType "scrypt", not for "rfc"
        "KeySizeInBytes": 32,
        "DerivationIterations": 0 // Only for DerivationType "rfc", not needed for "scrypt"

    }
    */

    /*
     * Simple text-based Encryption
     */

    this.encrypt = function (plainText, passPhrase, options) {
        var that = this;
        var rawPlainData;
        options = autocompleteOptions(options);
        var derivedKey = that.getDerivedKey(passPhrase, options);
        rawPlainData = string2arraybuffer(plainText);
        return webcryptoBinaryEncrypt(rawPlainData, derivedKey, options, true);
    }

    /*
     * Simple text-based Decryption
     */

    this.decrypt = function (encryptedData, passPhrase) {
        var that = this;
        var cO = JSON.parse(encryptedData);
        var dKey = that.getDerivedKey(passPhrase, cO); //This key is in PBKDF2
        var ciphertext = _base64ToArrayBuffer(cO.CipherOutputText);
        return webcryptoBinaryDecrypt(ciphertext, dKey, cO, true);
    }

    /*
    * Binary Decryption: rawEncryptedData must be in UintArray, passPhrase regular text
     * returnUtf8Text: if true, it returns text (assuming, text was encrypted and not binary data)
     * returnUtf8Text: if false, it returns binary
    */

    this.decryptBinary = function (rawEncryptedData, passPhrase, options, returnUtf8Text = false) {
        var that = this;
        var derivedKey = that.getDerivedKey(passPhrase, options);
        return webcryptoBinaryDecrypt(rawEncryptedData, derivedKey, options, returnUtf8Text);
    }

    /*
    * Binary Decryption with derived Key: as decryptBinary, but with derived key in Uint8array.
     * This has the purpose that if deriving the key takes a lot of time and you have multiple
     * files to decrypt, you just derive the key once and decrypt file by file without losing time.
    */

    this.decryptBinaryWithDerivedKey = function (rawEncryptedData, derivedKey, options, returnUtf8Text = false) {
        return webcryptoBinaryDecrypt(rawEncryptedData, derivedKey, options, returnUtf8Text);
    }

    /*
    * Binary Encryption with derived Key: Encrypt binary data
    */

    this.encryptBinary = function (rawPlainData, derivedKey, options, returnFullCryptoObject = false) {
        options = autocompleteOptions(options);
        return webcryptoBinaryEncrypt(rawPlainData, derivedKey, options, returnFullCryptoObject);
    }


    // To manually derive a crypto key, e. g. a Scrypt-key
    // Returns PBKDF2 key
    //

    this.getDerivedKey = function(passPhrase, options)
    {
        var cO = options;
        //Encoding the Salt in from UTF8 to byte array
        var Salt = new buffer.SlowBuffer(cO.Salt, 'hex');
        //CryptoJS.enc.Base64.parse(cO["Salt"]);
        //Creating the Vector Key
        var DerivedKey;

        //Creating the key in PBKDF2 format to be used during the decryption
        if (cO["DerivationType"] == "scrypt") {
            var sc = new scryptHandler();
            DerivedKey = hexStringToUint8Array(sc.GetOnlyHashInHexString(passPhrase, cO));
        } else {
            Salt = CryptoJS.enc.Hex.parse(cO.Salt);
            var Pass = CryptoJS.enc.Utf8.parse(passPhrase);
            var pass2 = Pass.toString(CryptoJS.enc.Utf8);
            DerivedKey =
                CryptoJS.PBKDF2(pass2, Salt, { keySize: cO["KeySizeInBytes"] * 8 / 32, iterations: cO["DerivationIterations"] });
            DerivedKey = CryptoJS.enc.Hex.stringify(DerivedKey);
            DerivedKey = new buffer.SlowBuffer(DerivedKey, 'hex');
        }
        return DerivedKey;
    }

    this.decryptAesZipEntry = async function(zipFilePassword, encryptedDataInUint8Array, isCompressed=false){
        var decHandle = new AESDecrypt(zipFilePassword, false, 3); // 3 = encryption strength. 3 = 256 Bits // true = signed --> check if correct encryption
        var decryptedPart1 = await decHandle.append(encryptedDataInUint8Array);
        const result = await decHandle.flush();
        if (!result.valid) {
            throw new Error("Error: The signature of the ZIP AES encryption is incorrect!");
        }
        var decryptedPart2 = result.data;
        var decryptedCombined = new Uint8Array(decryptedPart1.length + decryptedPart2.length);
        decryptedCombined.set(decryptedPart1);
        decryptedCombined.set(decryptedPart2, decryptedPart1.length);
        if(isCompressed){
            try{
                let zipHandle = new ZipInflate();
                let decompressed = await zipHandle.append(decryptedCombined);
                await zipHandle.flush();
                return decompressed;
            }
            catch(e){
               throw new Error("Error: Could not decompress ZIP after decrypting: " + e.message);
            }
            
        }
        return decryptedCombined;
    }


    // return Utf8Text true = returns text, else returns binary
    function webcryptoBinaryDecrypt(rawEncryptedData, derivedKey, options, returnUtf8Text = true) {
        return new Promise(function (resolve, reject) {
            var iv = _base64ToArrayBuffer(options.AesRijndaelIv);
            crypto.subtle.importKey("raw", derivedKey, "AES-CBC", false, ["encrypt", 'decrypt'])
                .then(function (key) {
                    return crypto.subtle.decrypt({ 'name': 'AES-CBC', iv: iv }, key, rawEncryptedData);
                },
                    reject)
                .then(function (plainText) {
                    if (returnUtf8Text) {
                        resolve(new TextDecoder("utf-8").decode(plainText));
                    } else {
                        resolve(plainText);
                    }

                },
                    reject);
        });

    }


     

    // Send rawPlainData in Uint8Array!
    function webcryptoBinaryEncrypt(rawPlainData, derivedKey, options, returnFullCryptoObject = false) {
        return new Promise(function (resolve, reject) {
            var iv = _base64ToArrayBuffer(options.AesRijndaelIv);
            crypto.subtle.importKey("raw", derivedKey, 'AES-CBC', false, ["encrypt", 'decrypt'])
                .then(function (key) {
                    return crypto.subtle.encrypt({ 'name': 'AES-CBC', iv: iv }, key, rawPlainData);
                    },
                    reject)
                .then(function (cipherText) {
                    if (returnFullCryptoObject) {
                            options.CipherOutputText = _arrayBufferToBase64(cipherText);
                            resolve(JSON.stringify(options));
                        } else {
                            resolve(cipherText);
                        }
                    },
                    reject);
        });
    }

    function autocompleteOptions(options) {
        var rijndaelIv;
        var salt;
        if (options == null || options.AesRijndaelIv == null || options.Salt == null) {
            var array1 = new Uint8Array(16);
            var array2 = new Uint8Array(32);
            rijndaelIv = _arrayBufferToBase64(window.crypto.getRandomValues(array1));
            salt = arrayBufferToHex(window.crypto.getRandomValues(array2));
        
        }
        if (options == null) { // Scrypt is default (not rfc)
            options = {
                "DerivationType": "scrypt",
                "Salt": salt, //(can be empty or null, then string is automatically created)
                "Cost": 16384, //(the "N" of scrypt, default is 16384)
                "BlockSize": 8, // (the "r", default is 8)
                "Parallel": 1, // (the "p", default is 1)
                "KeySizeInBytes": 32, // (default is 32),
                "AesRijndaelIv": rijndaelIv
            }
        } else {
            // if one of the options exist, but others not
            ('DerivationType' in options) || (options.DerivationType = "scrypt");
            ('Salt' in options) || (options.Salt = salt);
            ('Cost' in options) || (options.Cost = 16384);
            ('BlockSize' in options) || (options.BlockSize = 8);
            ('Parallel' in options) || (options.Parallel = 1);
            ('KeySizeInBytes' in options) || (options.KeySizeInBytes = 32);
            ('DerivationIterations' in options) || (options.DerivationIterations = 10000);
            ('AesRijndaelIv' in options) || (options.AesRijndaelIv = rijndaelIv);
        }
        return options;
    }



   
}




