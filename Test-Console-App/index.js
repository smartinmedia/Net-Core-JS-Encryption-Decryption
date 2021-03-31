// Test Encryption / Decryption
// This is the ciphertext, which was encrypted by C# to check the interchangeability:
//var encryptedBase64FromCSharp = '{"DerivationType": "scrypt","Salt": "MmTt71gekdK62HbCD2ZUUkYBwVpMB6aWzYGJg+eUvBM=","Cost": 16384,"BlockSize": 8,"Parallel": 1,"KeySizeInBytes": 32,"DerivationIterations": 0,"AesRijndaelIv": "eIUwJ0pzcnr1HmSIVX4Qhw==","CipherOutputText": "BBhxsgDxth1u03appq/WIlXV+wbhUm7CMLZ/NazdJRA="}';
//var encryptedBase64FromCSharp ='{"DerivationType": "rfc","Salt": "ZPVKtxxU+ZOBcA5FMCGIrLCJhItZQr9xkhzw4GyXk1A=","Cost": 0,"BlockSize": 0,"Parallel": 0,"KeySizeInBytes": 32,"DerivationIterations": 10000,"AesRijndaelIv": "3aF7jwcjXiEkuPOn8oqK0g==","CipherOutputText": "rKn+tl0Y4xyPqtQ/kfz1yhgh0pckTHxhayLAPNF4vIA="}';
var encryptedFromCSharpWithScrypt =
    '{"DerivationType": "scrypt", "Salt": "3a069e9126af66a839067f8a272081136d8ce63ed72176dc8a29973d2b15361f", "Cost": 16384, "BlockSize": 8, "Parallel": 1, "KeySizeInBytes": 32, "DerivationIterations": 0, "AesRijndaelIv": "NrCMq2XZ/woLCBq2haKPtQ==", "CipherOutputText": "8Llal3i445vIVWRIHsMQHdaJlpYoubcjmFczH0t7tEA="}';

var encryptedFromCSharpWithPbkdf2 =
    '{"DerivationType":"pbkdf2","Salt":"006385e0434e50d2cbc3c29f1b10bb2edf419a046867d75967ee737ec53279f2","Cost":0,"BlockSize":0,"Parallel":0,"KeySizeInBytes":32,"DerivationIterations":10000,"AesRijndaelIv":"gkuFCtlPvmy0v5QPYTVSsQ==","CipherOutputText":"TrvyuD93z+shiga6E56eZFzFVBbvMp6Pic0C8PhHaeU="}';


var passPhrase = "This_is_my_password!";
var outputText;
var spanEnc = document.getElementById("output"); 
var ele = document.getElementById("output-binary");
var eH = new encryptionHandler();
var decryptedFromCSharp;
var encryptTextWithJs;

eH.decrypt(encryptedFromCSharpWithScrypt, passPhrase).then(function (decrypted) {
    decryptedFromCSharp = decrypted;
    outputText = "The decrypted text from C# with SCRYPT: " + decrypted;
    spanEnc.innerHTML = outputText;
    return decrypted;
})
    .then(function(decrypted) {
        encryptTextWithJs = eH.encrypt(decrypted, "This_is_my_password!");
        return encryptTextWithJs;
    })
    .then(function(encryptTextWithJs) {
        eH.decrypt(encryptTextWithJs, "This_is_my_password!").then(function(decryptedTextWithJs) {
            outputText += "<br>And now this (SCRYPT derived key encryption) was encrypted and decrypted again with JS: " + decryptedTextWithJs;
            spanEnc.innerHTML = outputText;
        });

    });

eH.decrypt(encryptedFromCSharpWithPbkdf2, passPhrase).then(function (decrypted) {
        decryptedFromCSharp = decrypted;
        outputText += "<br/><br/>The decrypted text from C# with PBKDF2: " + decrypted;
        spanEnc.innerHTML = outputText;
        return decrypted;
    })
        .then(function(decrypted) {
            encryptTextWithJs = eH.encrypt(decrypted, "This_is_my_password!");
            return encryptTextWithJs;
        })
        .then(function(encryptTextWithJs) {
            eH.decrypt(encryptTextWithJs, "This_is_my_password!").then(function(decryptedTextWithJs) {
                outputText += "<br>And now this (PBKDF2 derived key encryption) was encrypted and decrypted again with JS: " + decryptedTextWithJs;
                spanEnc.innerHTML = outputText;
            });
    
        });    

document.getElementById('clear').addEventListener('click',
    function(evt) {
        var el = document.getElementById("cartmanimg");
        if (el) {
            el.parentNode.removeChild(el);

        }
    
    });

/*
    * Test Binary Decryption of an image 
    * and display it
    * To test it, load the file "cartman.enc". It should display cartman
    */

var jsonBinarySetting =
    {"DerivationType":"scrypt","Salt":"546869735f69735f6d795f73616c74","Cost":16384,"BlockSize":8,"Parallel":1,"KeySizeInBytes":32,"DerivationIterations":0,"AesRijndaelIv":"aXZfaXNfMTZfbG9uZ19fXw==","CipherOutputText":null};

document.getElementById('fileOpen').addEventListener('change',
    function (evt) {
        
        var file = evt.target.files[0],
            reader = new FileReader();

        reader.onload = function(e) {
            var data = e.target.result;
            var derivedKey = eH.getDerivedKey("This_is_my_password!", jsonBinarySetting);
            var t0 = performance.now();
            eH.decryptBinaryWithDerivedKey(data, derivedKey, jsonBinarySetting)
                .then(function(decrypted) {
                    var t1 = performance.now();
                    var feedback = document.getElementById("information");
                    var response = 'Information: The encrypted data is ' +
                        decrypted.byteLength +
                        ' bytes long' +
                        "<br/>and action took: " +
                        (t1 - t0) +
                        " milliseconds."; // encrypted is an ArrayBuffer
                    feedback.innerHTML = response;

                    var base64String = _arrayBufferToBase64(decrypted);  //CryptoJS.enc.Base64.stringify(decrypted);
                    var imgUrl = 'data:image/png;base64,' + base64String;
                    var img = document.createElement("img");
                    img.setAttribute("id", "cartmanimg");
                    img.src = imgUrl;
                    ele.appendChild(img);
                })
                .catch(console.error);
        }

        reader.readAsArrayBuffer(file);  
        });

document.getElementById('fileOpen2').addEventListener('change',
    function (evt) {
        
        var file = evt.target.files[0],
            reader = new FileReader();

        reader.onload = async function(e) {
            var arrBuf = e.target.result;
            var encryptedDataInUint8Array = new Uint8Array(arrBuf);
            var t0 = performance.now();
            var zipFilePassword = "3rQA6zJX-sQwHT4iA-GWDoYjXn-Cuow6uBp";
            try{
                var decryptedFile = await eH.decryptAesZipEntry(zipFilePassword, encryptedDataInUint8Array);
            }
            catch(e){
                console.log("AES Decryption key for ZIP file is wrong or possibly other error :-(!");
                return;
            }
            var t1 = performance.now();
            var feedback = document.getElementById("information2");
            feedback.innerHTML += "Decrypting raw (uncompressed) ZIP file and action took: " + (t1 - t0) + " milliseconds."; 

        }

        reader.readAsArrayBuffer(file);  
        });



//
// Test Scrypt
//
var outputText2 =
    "<br><br>Testing Scrypt<br> with password = 'This_is_my_password!' and salt = 'This_is_my_SALT!'";
var password = "This_is_my_password!";
var saltString = "This_is_my_SALT!";

//SALT must be delivered as Hex!!
var wr = CryptoJS.enc.Utf8.parse(saltString);
var salt = CryptoJS.enc.Hex.stringify(wr);

var t0 = (new Date()).getTime(); //To measure time!
/*
    You can add any of these options
var options =
    {
            "salt": string, //(can be empty or null, then string is automatically created)
            "cost": int, //(the "N" of scrypt, default is 16384)
            "blockSize": int, // (the "r", default is 8)
            "parallel": int, // (the "p", default is 1)
            "derivedKeyLength": int // (default is 32)
    }
*/
var sH = new scryptHandler();

var options = { "salt": salt };
var callback = function(error, progress, key) {
    if (error) {
        outputText2 += "There was an error: " + error;
    } else if (key) {
        outputText2 += "<br/>The key string for password " + password + " is: " + key;
        outputText2 += "<br/>It is compatible with C# as long as you leave maxThreads in C# at null";
        outputText2 += "<br>Execution time: " + (((new Date()).getTime() - t0) / 1000) + ' seconds';
        var spanScrypt = document.getElementById("outputScrypt");
        spanScrypt.innerHTML = outputText2;
        sH.comparePasswordWithHash(password,
            key,
            function(isTheSame) {
                if (isTheSame) {

                    var spanScrypt = document.getElementById("outputScrypt");
                    spanScrypt.innerHTML =
                        spanScrypt.innerHTML + "<br/>Checking the password vs hash: matches!";

                } else {
                    var spanScrypt = document.getElementById("outputScrypt");
                    spanScrypt.innerHTML =
                        spanScrypt.innerHTML + "<br/>Checking the password vs hash: does not match!";

                }
            });

    } else if (progress) {
        var spanProgress = document.getElementById("progress");

        spanProgress.innerHTML = (((progress * 100).toFixed()).toString() + "%");
    }

}

sH.Hash(password, options, callback);
var spanScryptsynch = document.getElementById("outputScrypt-synch");

var sH2 = new scryptHandler();
var synchKey = sH2.Hash(passPhrase, options);
spanScryptsynch.innerHTML =
    "<br/><br/>You can also get the key synchronously without callback function: " +
    synchKey;
if (sH2.comparePasswordWithHash(passPhrase, synchKey)) {
    spanScryptsynch.innerHTML +=
        "<br/>And the derived hash key matches with the test (also in synchronous mode)!";
} else {
    spanScryptsynch.innerHTML +=
        "<br/>The derived hash key do not match with the test (in synchronous mode)!";
}

var testHash = sH2.Hash("This_is_my_password!", { "Salt": transformTextToHex("1") });
spanScryptsynch.innerHTML +=
    "<br/><br/>The derived password with a given string Salt is: " + testHash;

function _arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}