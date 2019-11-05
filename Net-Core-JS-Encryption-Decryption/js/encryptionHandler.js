function encryptionHandler() {

    this.decrypt = function (encryptedData, passPhrase) {
        var cO = JSON.parse(encryptedData);

        //var bytes = atob(encryptedData);

        /*var saltUtf8 = bytes.substring(0, 32);
        var ivUtf8 = bytes.substring(32, 48);
        var ciphertextUtf8 = bytes.substring(48, bytes.length);
        */

        //Encoding the Salt in from UTF8 to byte array
        var Salt = CryptoJS.enc.Base64.parse(cO["Salt"]);
        //Creating the Vector Key
        var Iv = CryptoJS.enc.Base64.parse(cO["AesRijndaelIv"]);
        //Encoding the Password in from UTF8 to byte array

        var DerivedKey;

        //Creating the key in PBKDF2 format to be used during the decryption
        if (cO["DerivationType"] == "scrypt") {
            var sc = new scryptHandler();
            DerivedKey = CryptoJS.enc.Hex.parse(sc.GetOnlyHashInHexString(passPhrase, cO));
        } else {
            var Pass = CryptoJS.enc.Utf8.parse(passPhrase);
            DerivedKey =
                CryptoJS.PBKDF2(Pass.toString(CryptoJS.enc.Utf8), Salt, { keySize: cO["KeySizeInBytes"] * 8 / 32, iterations: cO["DerivationIterations"] });
        }
        
        //Enclosing the test to be decrypted in a CipherParams object as supported by the CryptoJS libarary
        var cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(cO["CipherOutputText"])
        });

        //Decrypting the string contained in cipherParams using the PBKDF2 key
        var decrypted = CryptoJS.AES.decrypt(cipherParams,
            DerivedKey,
            { mode: CryptoJS.mode.CBC, iv: Iv, padding: CryptoJS.pad.Pkcs7 });
        var decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

        return decryptedText;

    }

    this.getDerivedKey = function(passPhrase, options)
    {
        var cO = options;
        //Encoding the Salt in from UTF8 to byte array
        var Salt = CryptoJS.enc.Base64.parse(cO["Salt"]);
        //Creating the Vector Key
       
        var DerivedKey;

        //Creating the key in PBKDF2 format to be used during the decryption
        if (cO["DerivationType"] == "scrypt") {
            var sc = new scryptHandler();
            DerivedKey = CryptoJS.enc.Hex.parse(sc.GetOnlyHashInHexString(passPhrase, cO));
        } else {
            var Pass = CryptoJS.enc.Utf8.parse(passPhrase);
            DerivedKey =
                CryptoJS.PBKDF2(Pass.toString(CryptoJS.enc.Utf8), Salt, { keySize: cO["KeySizeInBytes"] * 8 / 32, iterations: cO["DerivationIterations"] });
        }
        return DerivedKey;
    }

    /*
     * First, get your derived key, then you can decrypt binary data to binary with this
     *
     */

    this.decryptBinaryWithParameters = function (rawEncryptedData, DerivedKey, options) {

        var cO = options;
        //Encoding the Salt in from UTF8 to byte array
        var Iv = CryptoJS.enc.Base64.parse(cO["AesRijndaelIv"]);
        //Encoding the Password in from UTF8 to byte array

        
        //Enclosing the test to be decrypted in a CipherParams object as supported by the CryptoJS libarary
        var cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: rawEncryptedData
        });

        //Decrypting the string contained in cipherParams using the PBKDF2 key
        var decrypted = CryptoJS.AES.decrypt(cipherParams,
            DerivedKey,
            { mode: CryptoJS.mode.CBC, iv: Iv, padding: CryptoJS.pad.Pkcs7 });
        //var decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

        return decrypted;
    }
    
    /*
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
     

    this.encrypt = function (plainText, passPhrase, options) {

        if (options == null) { // Scrypt is default (not rfc)
            options = {
                "DerivationType" : "scrypt",
                "Salt": CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(32)), //(can be empty or null, then string is automatically created)
                "Cost": 16384, //(the "N" of scrypt, default is 16384)
                "BlockSize": 8, // (the "r", default is 8)
                "Parallel": 1, // (the "p", default is 1)
                "KeySizeInBytes": 32 // (default is 32)
            }
        }


        // if one of the options exist, but others not
        ('DerivationType' in options) || (options.DerivationType = "scrypt");
        ('Salt' in options) || (options.Salt = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(32)));
        ('Cost' in options) || (options.Cost = 16384);
        ('BlockSize' in options) || (options.BlockSize = 8);
        ('Parallel' in options) || (options.Parallel = 1);
        ('KeySizeInBytes' in options) || (options.KeySizeInBytes = 32);
        ('DerivationIterations' in options) || (options.DerivationIterations = 10000);


        //Encoding the Salt from Hex
        var Salt = CryptoJS.enc.Hex.parse(options.Salt);
        //Creating the Vector Key
        var Iv = CryptoJS.lib.WordArray.random(16);
        options.AesRijndaelIv = CryptoJS.enc.Base64.stringify(Iv);

        var key;
        if (options.DerivationType == "scrypt") {
            var sc = new scryptHandler();
            key = CryptoJS.enc.Hex.parse(sc.GetOnlyHashInHexString(passPhrase, options));
             
        } else { // DerivationType = "rfc"
            //Encoding the Password in from UTF8 to byte array
            Pass = CryptoJS.enc.Utf8.parse(passPhrase);
            key =
                CryptoJS.PBKDF2(Pass.toString(CryptoJS.enc.Utf8), Salt, { keySize: options.KeySizeInBytes * 8 / 32, iterations: options.DerivationIterations });

        }

        //Creating the key in PBKDF2 format to be used during the decryption
        
        //Decrypting the string contained in cipherParams using the PBKDF2 key
        var encrypted = CryptoJS.AES.encrypt(plainText,
            key,
            { mode: CryptoJS.mode.CBC, iv: Iv});

        options.CipherOutputText = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
        return JSON.stringify(options);
    }

    this.transformTextToHex = function(text) {
        var utf8 = CryptoJS.enc.Utf8.parse(text);
        return CryptoJS.enc.Hex.stringify(utf8);
    }

}




