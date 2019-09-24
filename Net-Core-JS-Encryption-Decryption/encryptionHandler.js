function encryptionHandler() {

    this.decrypt = function(encryptedData, passPhrase) {
        var parts = encryptedData.split(":"); //SALT:IV:CIPHERTEXT

        //var bytes = atob(encryptedData);

        /*var saltUtf8 = bytes.substring(0, 32);
        var ivUtf8 = bytes.substring(32, 48);
        var ciphertextUtf8 = bytes.substring(48, bytes.length);
        */

        //Encoding the Salt in from UTF8 to byte array
        var Salt = CryptoJS.enc.Base64.parse(parts[0]);
        //Creating the Vector Key
        var iv = CryptoJS.enc.Base64.parse(parts[1]);
        //Encoding the Password in from UTF8 to byte array
        var Pass = CryptoJS.enc.Utf8.parse(passPhrase);
        //Creating the key in PBKDF2 format to be used during the decryption
        var key256Bits1000Iterations =
            CryptoJS.PBKDF2(Pass.toString(CryptoJS.enc.Utf8), Salt, { keySize: 256 / 32, iterations: 1000 });
        //Enclosing the test to be decrypted in a CipherParams object as supported by the CryptoJS libarary
        var cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(parts[2])
        });

        //Decrypting the string contained in cipherParams using the PBKDF2 key
        var decrypted = CryptoJS.AES.decrypt(cipherParams,
            key256Bits1000Iterations,
            { mode: CryptoJS.mode.CBC, iv: iv, padding: CryptoJS.pad.Pkcs7 });
        var decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

        return decryptedText;

    }

    this.encrypt = function(plainText, passPhrase) {

        //Encoding the Salt in from UTF8 to byte array
        var Salt = CryptoJS.lib.WordArray.random(32);
        //Creating the Vector Key
        var Iv = CryptoJS.lib.WordArray.random(16);
        //Encoding the Password in from UTF8 to byte array
        var Pass = CryptoJS.enc.Utf8.parse(passPhrase);
        //Creating the key in PBKDF2 format to be used during the decryption
        var key256Bits1000Iterations =
            CryptoJS.PBKDF2(Pass.toString(CryptoJS.enc.Utf8), Salt, { keySize: 256 / 32, iterations: 1000 });

        //Decrypting the string contained in cipherParams using the PBKDF2 key
        var encrypted = CryptoJS.AES.encrypt(plainText,
            key256Bits1000Iterations,
            { mode: CryptoJS.mode.CBC, iv: Iv});

        var encryptedText = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);//encrypted.toString(CryptoJS.enc.Utf8);
        var cipherWithSaltAndIv = CryptoJS.enc.Base64.stringify(Salt) +
            ":" +
            CryptoJS.enc.Base64.stringify(Iv) +
            ":" +
            encryptedText;
        return cipherWithSaltAndIv;
    }
}




