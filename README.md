# Encryption/Decryption JS/C# - Encrypt, decrypt and securely hash with Scrypt between .NET Core and JavaScript

## Edward Snowden writes...
*"Encryption is the single best hope for fighting surveillance of any kind. If all our data, including our communications, were enciphered in this fashion, from end to end…then no government - no entity conceivable under our current knowledge of physics, for that matter - would be able to understand them."*

## About us
We are a company (Smart In Media GmbH & Co. KG, https://www.smartinmedia.com) and believe in the importance of open source, thus we donate this piece to the community!

## Background/Why?
I was working on a medical project (https://www.easyradiology.net) and wanted to encrypt patient data in C#. The key/password would be printed on a piece of paper for patients.
When the patient opens a link, the encrypted data are sent to the browser and the browser can then decrypt only of the client side with the
server being ignorant to the password (to protect patient data). Can't be too difficult to use the AES algorithm (= Rijndael), which is implemented in both,
C# and JS and then encrypt decrypt in any direction, right? Unfortunately not. I found out that the difficulties lie in the preparation of the key, 
the "Salt", the "IV", the iterations, etc. Do you get it? Exactly, me neither. Now, I figured everything out for you and will explain it step by step,
so everyone gets peace of mind :)

Also, I learnt: hashing the user password is of course important before storing it in the database, so that attackers cannot harvest user passwords. However, 
it is really important to minimize the risk of dictionary attacks. Scrypt is one of the later hashing technologies and adds complexity by adapting to hardware (and making it harder to be broken by GPUs).

## What's the functionality?

3 solutions:<br/>1. You need a plaintext and a password and can call the encrypt and decrypt function in both, C# and JS. The encrypted text is interchangeable between
the 2 languages. The selected encryption algorithm is AES. The test console application shows it for C# and for JS (just run  the index.html for JS).
Will be explained below.
<br/>2. Hashing your users' passwords. With Scrypt, you can securely hash and store your users' passwords. I also implemented Scrypt into the AES key derivation, which makes it "safer" than older approaches like RFC2898. However - with the AES encryption, you can select either (default is Scrypt).
<br/>3. Also, the library has a password generator, which you can give a selection of characters, you want it to use (e. g. "abcdefghijklmnopqrstuvwxyz0123456789")
and it will figure out the rest.

## A little bit cryptography
Of note:<br/>
**Plaintext:** The text to be encrypted<br/>
**Passphrase:** The password/key<br/>
**Ciphertext:** The encrypted message/text<br/>
**Hash(ing):** If you store your user's passwords somewhere, you have to hash them!

**ENCRYPTION/DECRYPTION WITH AES**
First of all, the AES (advanced encryption standard) algorithm used here is safe against attacks. It is currently unbreakable and even the NSA, 
CIA, KGB won't be able to crack it. 
Having said that, it is important to be aware that even the best encryption can be compromised by a lot of factors: wrong implementation, weak passwords,
interception during key-exchange, etc.

AES is a *symmetric* encryption, which means that the same key is used for encryption as well as for decryption (opposed to asymmetric encryption with a 
public and a private key). Thus, the key exchange has to be safe and either use asymmetric encryption or a different channel (sending the key with 
e. g. a letter).<br/>
This library implemented random SALT and random IV (initialization vectors) for each message. This is in contrast to many examples of JS/C# AES encryption, 
which use a static SALT and IV.
Now, what are SALT and IV? I am sure, you have read about SALT before, because user passwords should always be stored "salted" in databases. 

<br/><br/>
**MORE ABOUT HASHING AND SALTING**
What is that hashing about anyway?<br/>
Let's assume, you have a database on your webserver, which stores user passwords. Then it is paramount to NOT store plaintext passwords in the database! Even renowned companies have screwed up this one badly!! E. g. Adobe, 500px, Dropbox have done a shitty job of storing user passwords, some of them (500px) with only MD5 security. Have a look at: https://haveibeenpwned.com/<br/>
So, a hash is the result of mathmatical "one-way functions". These are functions, where you can e. g. calculate a hash from the password, but you cannot "decrcypt" the hash to the password. If the attacker knows, which hashing algorithm was used (and hiding it is not a good protection), he can just take a dictionary, hash all words and compare them with the hacked password hashes to find out the user's password. So, to make live harder for the attacker, passwords of different users are hashed with different "SALTs". A SALT is just some random string/bytes, which are combined with the password. Then, the attacker would have to create a hashtable of the dictionary for each user individually. This makes cracking passwords harder. However, imagine, there is a celebrity among the users and the attacker just wants to focus on this one person. Then, creating a dictionary attack (salted) is not such a bad idea. One trick is to perform the hashing a lot of times, e. g. 10,000 times. This is time consuming and for each password try, it may take a fraction of a second. But, by the advent of powerful GPUs (like Nvidia), which can do many calculations simultaneously, the trick of performing e. g. 10,000x SHA1 was weakened. To counter this, **the hashing method "Scrypt"** was invented. Scrypt just 
takes more memory and makes it less infeasable for GPUs and attackers. E. g., if you set the settings of Scrypt (default values) to "cost" (N) to 16384, block size to 8 and parallel to 1,
then it takes appr. 1 second to calculate the hash - either in C# and in JS on an i7 processor with 12 GB RAM. 
So, with a dictionary attack, each iteration through the passwords would take 1 second per tested password. Let's assume, a user picks a password with a length of 
8 characters. The attacker knows that the user only uses 8 characters of A-Z, a-z, 0-9 and - and _ --> 64 different characters. So, we'd have 64^8 possibilities (281 trillion).
281 trillion seconds / 60 / 60 / 24 = 3 billion days or 8 million years to run through all (and 4 million years to run through 50% of the) passwords. 
Another great advantage is that with the same password (but different SALT), the ciphertext is always different. Thus, if I encrypt the exact same 
text as you do, it cannot happen that the result is the same and I then know, that you used the same password.
<br/><br/>
IV is pretty similar to a SALT. It is added to the plaintext. This means, even if you don't salt a password, because of the IV, every encryption of the same plaintext results in a 
different ciphertext, so it is harder for attackers.<br/>
This library creates random SALT and random IV for each encryption. SALT and IV are appended to the ciphertext and may be transmitted and communicated in the open.
Again, SALT and IV cannot (and don't have to) be hidden from the attacker. They are of no use to him, but are needed to decrypt. In this library, I introduced the Scrypt password derivation functionality into AES. This means, if your user's password is e. g. "Hello", Scrypt is used by default to create a 256 bit (32 byte) key from it. You can also use (by changing the options) the RFC2898 standard method, usually implemented in AES. On an i7 Laptop with 12 GB RAM, the Scrypt with parameters 16384, 8, 1, 32 use 0.18 seconds in C# and appr. 1 sec in JS. You can increase the 16384 to numbers, which are to the power of 2 to slow down the key derivation and make it harder on attackers.

## Get started here!

Let's see how we can encrypt / decrypt in C# and how to hash with Scrypt.
For hashing, you also have a function to compare a password with the hash. The hash contains all the settings of N, p, r, etc of Scrypt, so you don't need to worry about that.'

```csharp
	        var saltBuffer = new buffer.SlowBuffer(options.Salt, 'hex');

```


Now let's have a look at the Javascript part of encryption / decryption (have a look at the index.html) and usage of the Scrypt hashing of passwords.
The encryption / decryption is synchronous and pretty straight forward. The Scrypt part is a little bit more tricky. It's asynchronous, so you have to provide
a callback function with (error, progress, key). The progress is between 0 and 1. Check for "key" (that's our hash) to get the final key string containing
also the salt and all the parameters. So, e. g. if(key){//Here is everything, when the Scrypt hash is ready}.
As with C#, we also have a function to compare a password to the hash. So, when a user logs in and sends the password, you can compare
the password against the hash/key. The comparison may look a little bit confusing. This time, the callback function, which you 
send has to just check for "true" or "false".
You can run Scrypt asynchronously and get a progress (plus you can cancel) by passing a callback function.
Scrypt will pass the hash key to that callback function. If you omit the callback function, then Scrypt runs
synchronously and returns the key. So either, you run sH.Hash(password, options, callback);
or you run var key = sH.Hash(password, options);
Have a look at the "index.html". There is the entire test. You only need to include: 
<br/>
crypto-js.min.js, scrypt.min.js, encryptionHandler.js and scryptHandler.js with your code.

```javascript
	   // Test AES
            // This is the ciphertext, which was encrypted by C# to check the interchangeability:
            //var encryptedBase64FromCSharp = '{"DerivationType": "scrypt","Salt": "MmTt71gekdK62HbCD2ZUUkYBwVpMB6aWzYGJg+eUvBM=","Cost": 16384,"BlockSize": 8,"Parallel": 1,"KeySizeInBytes": 32,"DerivationIterations": 0,"AesRijndaelIv": "eIUwJ0pzcnr1HmSIVX4Qhw==","CipherOutputText": "BBhxsgDxth1u03appq/WIlXV+wbhUm7CMLZ/NazdJRA="}';
            //var encryptedBase64FromCSharp ='{"DerivationType": "rfc","Salt": "ZPVKtxxU+ZOBcA5FMCGIrLCJhItZQr9xkhzw4GyXk1A=","Cost": 0,"BlockSize": 0,"Parallel": 0,"KeySizeInBytes": 32,"DerivationIterations": 10000,"AesRijndaelIv": "3aF7jwcjXiEkuPOn8oqK0g==","CipherOutputText": "rKn+tl0Y4xyPqtQ/kfz1yhgh0pckTHxhayLAPNF4vIA="}';
            var encryptedBase64FromCSharp = '{"DerivationType": "scrypt", "Salt": "3a069e9126af66a839067f8a272081136d8ce63ed72176dc8a29973d2b15361f", "Cost": 16384, "BlockSize": 8, "Parallel": 1, "KeySizeInBytes": 32, "DerivationIterations": 0, "AesRijndaelIv": "NrCMq2XZ/woLCBq2haKPtQ==", "CipherOutputText": "8Llal3i445vIVWRIHsMQHdaJlpYoubcjmFczH0t7tEA="}';
            var passPhrase = "This_is_my_password!";

            var eH = new encryptionHandler();


            var decryptedFromCSharp = eH.decrypt(encryptedBase64FromCSharp, passPhrase);

            var spanEnc = document.getElementById("output");


            var outputText = "The decrypted text from C#: " + decryptedFromCSharp;
            spanEnc.innerHTML = outputText;
            var encryptTextWithJs = eH.encrypt(decryptedFromCSharp, "This_is_my_password!");

            var decryptedTextWithJs = eH.decrypt(encryptTextWithJs, "This_is_my_password!");
            outputText += "<br>And now this was encrypted and decrypted again with JS: " + decryptedTextWithJs;
            spanEnc.innerHTML = outputText;

            //
            // Test Scrypt
            //
            var outputText2 = "<br><br>Testing Scrypt<br> with password = 'This_is_my_password!' and salt = 'This_is_my_SALT!'";
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
            var callback = function (error, progress, key) {
                if (error) {
                    outputText2 += "There was an error: " + error;
                }
                else if (key) {
                    outputText2 += "<br/>The key string for password " + password + " is: " + key;
                    outputText2 += "<br/>It is compatible with C# as long as you leave maxThreads in C# at null";
                    outputText2 += "<br>Execution time: " + (((new Date()).getTime() - t0) / 1000) + ' seconds';
                    var spanScrypt = document.getElementById("outputScrypt");
                    spanScrypt.innerHTML = outputText2;
                    sH.comparePasswordWithHash(password,
                        key,
                        function (isTheSame) {
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

                }

                else if (progress) {
                    var spanProgress = document.getElementById("progress");

                    spanProgress.innerHTML = (((progress * 100).toFixed()).toString() + "%");
                }

            }

            sH.Hash(password, options, callback);
            var spanScryptsynch = document.getElementById("outputScrypt-synch");
            var sH2 = new scryptHandler();
            var synchKey = sH2.Hash(passPhrase, options);
            spanScryptsynch.innerHTML = "<br/><br/>You can also get the key synchronously without callback function: " +
                synchKey;
            if (sH2.comparePasswordWithHash(passPhrase, synchKey)) {
                spanScryptsynch.innerHTML +=
                    "<br/>And the derived hash key matches with the test (also in synchronous mode)!";
            } else {
                spanScryptsynch.innerHTML +=
                    "<br/>The derived hash key do not match with the test (in synchronous mode)!";
            }

```


## That's all folks, I hope it works well for you. Please don't forget to donate!!!
