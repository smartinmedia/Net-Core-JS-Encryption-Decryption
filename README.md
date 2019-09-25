# Encryption/Decryption JS/C# - Encrypt and decrypt between .NET Core and JavaScript

## Edward Snowden writes...
"Encryption is the single best hope for fighting surveillance of any kind. If all our data, including our communications, were enciphered in this fashion, from end to end…then no government—no entity conceivable under our current knowledge of physics, for that matter—would be able to understand them."

## About us
We are a company (Smart In Media GmbH & Co. KG, https://www.smartinmedia.com) and believe in the importance of open source, thus we donate this piece to the community!

## Background/Why?
I was working on a medical project (https://www.easyradiology.net) and wanted to encrypt patient data in C#. The key/password would be printed on a piece of paper for patients.
When the patient opens a link, the encrypted data are sent to the browser and the browser can then decrypt only of the client side with the
server being ignorant to the password (to protect patient data). Can't be too difficult to use the AES algorithm (= Rijndael), which is implemented in both,
C# and JS and then encrypt decrypt in any direction, right? Unfortunately not. I found out that the difficulties lie in the preparation of the key, 
the "Salt", the "IV", the iterations, etc. Do you get it? Exactly, me neither. Now, I figured everything out for you and will explain it step by step,
so everyone gets peace of mind :)

## What's the functionality?

Easy: You need a plaintext and a password and can call the encrypt and decrypt function in both, C# and JS. The encrypted text is interchangeable between
the 2 languages. The test console application shows it for C# and for JS (just run  the index.html for JS).
Will be explained below.
Also, the library has a password generator, which you can give a selection of characters, you want it to use (e. g. "abcdefghijklmnopqrstuvwxyz0123456789")
and it will figure out the rest.

## A little bit cryptography
Of note:
Plaintext: The text to be encrypted
Passphrase: The password/key
Ciphertext: The encrypted message/text
First of all, the AES (advanced encryption standard) algorithm used here is safe against attacks. It is currently unbreakable and even the NSA, 
CIA, KGB won't be able to crack it. 
Having said that, it is important to be aware that even the best encryption can be compromised by a lot of factors: wrong implementation, weak passwords,
interception during key-exchange, etc.

AES is a symmetric encryption, which means that the same key is used for encryption as well as for decryption (opposed to asymmetric encryption with a 
public and a private key). Thus, the key exchange has to be safe and either use asymmetric encryption or a different channel (sending the key with 
e. g. a letter).
This library implemented random SALT and random IV (initialization vectors) for each message. This is in contrast to many examples of JS/C# AES encryption, 
which use a static SALT and IV.
Now, what are SALT and IV? I am sure, you have read about SALT before, because user passwords should always be stored "salted" in databases. 

A SALT in AES is comparable. It is mixed with the user password and run through e. g. 1,000 hash-processes ("iterations"). These iterations are
very time consuming. This results that an attacker cannot effectively create a dictionary (or brute force) attack, because he would have to 
SALT millions of passwords, each with 1,000 iterations, which would take forever. 
Another great advantage is that with the same password (but different SALT), the ciphertext is always different. Thus, if I encrypt the exact same 
text as you do, it cannot happen that the result is the same and I then know, that you used the same password.

IV is pretty similar. It is added to the plaintext. This means, even if you don't salt a password, because of the IV, every encryption of the same plaintext results in a 
different ciphertext, so it is harder for attackers.
This library creates random SALT and random IV for each encryption. SALT and IV are appended to the ciphertext and may be transmitted and communicated in the open.
Again, SALT and IV cannot (and don't have to) be hidden from the attacker. They are of no use to him, but are needed to decrypt.

## Get started here!

Let's see how we can encrypt / decrypt in C#

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

```


Now let's have a look at the Javascript part of encryption / decryption (have a look at the index.html)

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
```


## That's all folks, I hope it works well for you. Please don't forget to donate!!!
