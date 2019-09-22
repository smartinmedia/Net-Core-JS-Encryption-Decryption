function DecryptData(encryptedData) {
    /*
     * The encrypted data are a Base64 string.
     * After de-base64, the first 16 bytes are the AES IV,
     * the next 32 bytes are the AES SALT and the rest is
     * the ciphertext.
     *
     */
    var decryptedText = null;
    try {
        //Creating the Vector Key
        var iv = CryptoJS.enc.Hex.parse('a5s8d2e9c1721ae0e84ad660c472y1f3');
        //Encoding the Password in from UTF8 to byte array
        var Pass = CryptoJS.enc.Utf8.parse('Crypto');
        //Encoding the Salt in from UTF8 to byte array
        var Salt = CryptoJS.enc.Utf8.parse("cryptography123example");
        //Creating the key in PBKDF2 format to be used during the decryption
        var key256Bits1000Iterations = CryptoJS.PBKDF2(Pass.toString(CryptoJS.enc.Utf8), Salt, { keySize: 256 / 32, iterations: 1000 });
        //Enclosing the test to be decrypted in a CipherParams object as supported by the CryptoJS libarary
        var cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(encryptedData)
        });

        //Decrypting the string contained in cipherParams using the PBKDF2 key
        var decrypted = CryptoJS.AES.decrypt(cipherParams, key256Bits1000Iterations, { mode: CryptoJS.mode.CBC, iv: iv, padding: CryptoJS.pad.Pkcs7 });
        decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
        return decryptedText;
    }
    //Malformed UTF Data due to incorrect password
    catch (err) {
        return "";
    }
}