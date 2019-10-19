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

Easy: <br/>You need a plaintext and a password and can call the encrypt and decrypt function in both, C# and JS. The encrypted text is interchangeable between
the 2 languages. The test console application shows it for C# and for JS (just run  the index.html for JS).
Will be explained below.
Also, the library has a password generator, which you can give a selection of characters, you want it to use (e. g. "abcdefghijklmnopqrstuvwxyz0123456789")
and it will figure out the rest.

## A little bit cryptography
Of note:<br/>
**Plaintext:** The text to be encrypted<br/>
**Passphrase:** The password/key<br/>
**Ciphertext:** The encrypted message/text<br/>
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

A SALT in AES is comparable. It is mixed with the user password and run through e. g. 10,000 hash-processes ("iterations"). These iterations are
time consuming. This results that an attacker cannot effectively create a dictionary (or brute force) attack, because he would have to 
create a dictionary for each individually salted password, each with 10,000 iterations, which would take a long time. <br/>
<br/><br/>Recently however, the advent of powerful GPUs, which can do many calculations simultaneously, lowered the power of the iterations as they can 
be calculated very fast simultaneously. To make it even more difficult for attackers, **the hashing method "Scrypt"** was invented. This 
takes more memory and makes it less infeasable for attackers. E. g., if you set the settings of Scrypt (default values) to "cost" (N) to 16384, block size to 8 and parallel to 1,
then it takes appr. 1 second to calculate the hash - either in C# and in JS. 
So, with a dictionary attack, each iteration through the passwords would take 1 second per tested password. Let's assume, a user picks a password with a length of 
8 characters. The attacker knows that the user only uses 8 characters of A-Z, a-z, 0-9 and - and _ --> 64 different characters. So, we'd have 64^8 possibilities (281 trillion).
281 trillion seconds / 60 / 60 / 24 = 3 billion days or 8 million years to run through all (and 4 million years to run through 50% of the) passwords. 
Another great advantage is that with the same password (but different SALT), the ciphertext is always different. Thus, if I encrypt the exact same 
text as you do, it cannot happen that the result is the same and I then know, that you used the same password.
<br/><br/>
IV is pretty similar to a SALT. It is added to the plaintext. This means, even if you don't salt a password, because of the IV, every encryption of the same plaintext results in a 
different ciphertext, so it is harder for attackers.<br/>
This library creates random SALT and random IV for each encryption. SALT and IV are appended to the ciphertext and may be transmitted and communicated in the open.
Again, SALT and IV cannot (and don't have to) be hidden from the attacker. They are of no use to him, but are needed to decrypt.

## Get started here!

Let's see how we can encrypt / decrypt in C# and how to hash with Scrypt.
For hashing, you also have a function to compare a password with the hash. The hash contains all the settings of N, p, r, etc of Scrypt, so you don't need to worry about that.'

```csharp
	//Encrypt plain text in C# with a random password
    string plainText = "This is my secret text!";
    //You can also use the built in password generator!!
    //string passPhrase = PasswordGenerator.GenerateRandomPassword(20);
            
	string passPhrase = "This_is_my_password!";

    var enc = EncryptionHandler.Encrypt(plainText, passPhrase);
    Console.WriteLine("Plaintext: 'This is my secret text' with password 'This_is_my_password!' results in ciphertext: " + enc);

    var dec3 = EncryptionHandler.Decrypt(enc, passPhrase);
    Console.WriteLine("And decrypting again: " + dec3);
    Console.WriteLine("Please start the index.html to see the same in Javascript. Encryption / Decryption run in both ways and can be interchanged between C# and JS!");

	/*
             * Testing Scrypt 
             * The recommended parameters for interactive logins as of 2009 are
             * iterationCount=16384, blockSize=8, threadCount=1, those are the default values.
             * They should be increased as memory latency and CPU parallelism increases.
             */

            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();
            
            // NOW RUNNING SCRYPT
            string hashString = ScryptHandler.Hash(passPhrase, "This_is_my_SALT!", 16384);
            stopWatch.Stop();

            Console.WriteLine("\r\nTesting Scrypt with the password 'This_is_my_password!': " + hashString);
            bool compare = ScryptHandler.ComparePasswordWithHash("This_is_my_password!", hashString);
            if (compare)
            {
                Console.WriteLine("The password matches with the stored hash!");
            }
            else
            {
                Console.WriteLine("The password does not match with the stored hash!");
            }
            
            // Get the elapsed time as a TimeSpan value.
            TimeSpan ts = stopWatch.Elapsed;

            // Format and display the TimeSpan value.
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);
            Console.WriteLine("Time elapsed in HH:MM:SS (only for creating the hash, not checking): " + elapsedTime);
        }
```


Now let's have a look at the Javascript part of encryption / decryption (have a look at the index.html) and usage of the Scrypt hashing of passwords.
The encryption / decryption is synchronous and pretty straight forward. The Scrypt part is a little bit more tricky. It's asynchronous, so you have to provide
a callback function with (error, progress, key). The progress is between 0 and 1. Check for "key" (that's our hash) to get the final key string containing
also the salt and all the parameters. So, e. g. if(key){//Here is everything, when the Scrypt hash is ready}.
As with C#, we also have a function to compare a password to the hash. So, when a user logs in and sends the password, you can compare
the password against the hash/key. The comparison may look a little bit confusing. This time, the callback function, which you 
send has to just check for "true" or "false".
Have a look at the "index.html". There is the entire test. You only need to include: 
<br/>
crypto-js.min.js, scrypt.min.js, encryptionHandler.js and scryptHandler.js with your code.

```javascript
	// This is the ciphertext, which was encrypted by C# to check the interchangeability:
	var encryptedBase64FromCSharp = "uTkXNB+PSTjzwUCJbfAHVHd95YOlcJr38wbF08ZxqNw=:PNGRjWb5tOINneaVVf8+cw==:Aic+gosvLjTrCebzY8l/usTh+kWuE0v1xSWw7apYunI=";
    var passPhrase = "This_is_my_password!";

    var eH = new encryptionHandler();

    var decryptedFromCSharp = eH.decrypt(encryptedBase64FromCSharp, passPhrase);

	//Now encrypt again with JS
    var encryptTextWithJs = eH.encrypt(decryptedFromCSharp, "This_is_my_password!");
	//And decrypt again with JS
    var decryptedTextWithJs = eH.decrypt(encryptTextWithJs, "This_is_my_password!");

	//
            // Test Scrypt
            //
            var outputText2 = "<br><br>Testing Scrypt<br> with password = 'This_is_my_password!' and salt = 'This_is_my_SALT!'";
            var password = "This_is_my_password!";
            var salt = "This_is_my_SALT!";
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
                }
                else if (key) {
                    outputText2 += "<br/>The key string for password " + password +" is: " + key;
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

                }

                else if (progress) {
                    var spanProgress = document.getElementById("progress");

                    spanProgress.innerHTML = (((progress * 100).toFixed()).toString() + "%");
                }
                
            }

            sH.Hash(password, options, callback);

            //now testing the PW
            function testHash(password, hashString, callback) {

            }

```


## That's all folks, I hope it works well for you. Please don't forget to donate!!!
