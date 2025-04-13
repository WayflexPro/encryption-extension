/*


 _       __   ___   __  __   ______   __       ______   _  __
| |     / /  /   |  \ \/ /  / ____/  / /      / ____/  | |/ /
| | /| / /  / /| |   \  /  / /_     / /      / __/     |   / 
| |/ |/ /  / ___ |   / /  / __/    / /___   / /___    /   |  
|__/|__/  /_/  |_|  /_/  /_/      /_____/  /_____/   /_/|_|  
                                                                 
*/

// Name: Encryption
// ID: encryption
// Description: Provides a set of blocks to perform AES encryption/decryption, hash generation (SHA256, MD5), encoding/decoding (Base64, hex), and random key generation using the CryptoJS library.
// By: Wayflex <https://scratch.mit.edu/users/KEDeX/>
// License: GPL-3.0

(function (Scratch) {
    'use strict';
    if (typeof CryptoJS === "undefined") {
        var script = document.createElement("script");
        script.src = "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js";
        script.onload = function () {
            console.log("CryptoJS loaded");
        };
        document.head.appendChild(script);
    }

    class EncryptionExtension {
        getInfo() {
            return {
                id: 'encryption',
                name: 'Encryption',
                blocks: [
                    {
                        opcode: 'encrypt',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'encrypt [TEXT] with password [PASS]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Hello, world!'
                            },
                            PASS: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'secret'
                            }
                        }
                    },
                    {
                        opcode: 'decrypt',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'decrypt [TEXT] with password [PASS]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Encrypted text here'
                            },
                            PASS: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'secret'
                            }
                        }
                    },
                    {
                        opcode: 'encryptKeyIV',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'encrypt [TEXT] with key [KEY] and IV [IV]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Hello, world!'
                            },
                            KEY: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: '00112233445566778899aabbccddeeff'
                            },
                            IV: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: '0102030405060708'
                            }
                        }
                    },
                    {
                        opcode: 'decryptKeyIV',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'decrypt [TEXT] with key [KEY] and IV [IV]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Encrypted text here'
                            },
                            KEY: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: '00112233445566778899aabbccddeeff'
                            },
                            IV: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: '0102030405060708'
                            }
                        }
                    },
                    {
                        opcode: 'sha256',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'sha256 of [TEXT]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Hello, world!'
                            }
                        }
                    },
                    {
                        opcode: 'md5',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'md5 of [TEXT]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Hello, world!'
                            }
                        }
                    },
                    {
                        opcode: 'base64Encode',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'base64 encode [TEXT]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Hello, world!'
                            }
                        }
                    },
                    {
                        opcode: 'base64Decode',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'base64 decode [TEXT]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'SGVsbG8sIHdvcmxkIQ=='
                            }
                        }
                    },
                    {
                        opcode: 'hexEncode',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'hex encode [TEXT]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'Hello, world!'
                            }
                        }
                    },
                    {
                        opcode: 'hexDecode',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'hex decode [TEXT]',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: '48656c6c6f2c20776f726c6421'
                            }
                        }
                    },
                    {
                        opcode: 'generateRandomKey',
                        blockType: Scratch.BlockType.REPORTER,
                        text: 'generate random key of [BYTES] bytes',
                        arguments: {
                            BYTES: {
                                type: Scratch.ArgumentType.NUMBER,
                                defaultValue: 16
                            }
                        }
                    },
                    {
                        opcode: 'isValidAESCiphertext',
                        blockType: Scratch.BlockType.BOOLEAN,
                        text: 'is valid AES ciphertext [TEXT]?',
                        arguments: {
                            TEXT: {
                                type: Scratch.ArgumentType.STRING,
                                defaultValue: 'U2FsdGVkX1...'
                            }
                        }
                    }
                ]
            };
        }

        encrypt(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const ciphertext = CryptoJS.AES.encrypt(args.TEXT, args.PASS).toString();
                return ciphertext;
            } catch (e) {
                return "Error during encryption: " + e.message;
            }
        }

        decrypt(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const bytes = CryptoJS.AES.decrypt(args.TEXT, args.PASS);
                const plaintext = bytes.toString(CryptoJS.enc.Utf8);
                return plaintext || "Invalid password or ciphertext";
            } catch (e) {
                return "Error during decryption: " + e.message;
            }
        }

        encryptKeyIV(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const key = CryptoJS.enc.Hex.parse(args.KEY);
                const iv = CryptoJS.enc.Hex.parse(args.IV);
                const ciphertext = CryptoJS.AES.encrypt(args.TEXT, key, { iv: iv }).toString();
                return ciphertext;
            } catch (e) {
                return "Error during encryption with key/IV: " + e.message;
            }
        }

        decryptKeyIV(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const key = CryptoJS.enc.Hex.parse(args.KEY);
                const iv = CryptoJS.enc.Hex.parse(args.IV);
                const bytes = CryptoJS.AES.decrypt(args.TEXT, key, { iv: iv });
                const plaintext = bytes.toString(CryptoJS.enc.Utf8);
                return plaintext || "Invalid key/IV or ciphertext";
            } catch (e) {
                return "Error during decryption with key/IV: " + e.message;
            }
        }

        sha256(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                return CryptoJS.SHA256(args.TEXT).toString();
            } catch (e) {
                return "Error generating SHA256 hash: " + e.message;
            }
        }

        md5(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                return CryptoJS.MD5(args.TEXT).toString();
            } catch (e) {
                return "Error generating MD5 hash: " + e.message;
            }
        }

        base64Encode(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const wordArray = CryptoJS.enc.Utf8.parse(args.TEXT);
                return CryptoJS.enc.Base64.stringify(wordArray);
            } catch (e) {
                return "Error during Base64 encoding: " + e.message;
            }
        }

        base64Decode(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const parsedWordArray = CryptoJS.enc.Base64.parse(args.TEXT);
                return CryptoJS.enc.Utf8.stringify(parsedWordArray);
            } catch (e) {
                return "Error during Base64 decoding: " + e.message;
            }
        }

        hexEncode(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const wordArray = CryptoJS.enc.Utf8.parse(args.TEXT);
                return CryptoJS.enc.Hex.stringify(wordArray);
            } catch (e) {
                return "Error during Hex encoding: " + e.message;
            }
        }

        hexDecode(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const wordArray = CryptoJS.enc.Hex.parse(args.TEXT);
                return CryptoJS.enc.Utf8.stringify(wordArray);
            } catch (e) {
                return "Error during Hex decoding: " + e.message;
            }
        }

        generateRandomKey(args) {
            if (typeof CryptoJS === "undefined") {
                return "CryptoJS is not loaded yet.";
            }
            try {
                const bytes = parseInt(args.BYTES);
                const randomKey = CryptoJS.lib.WordArray.random(bytes);
                return randomKey.toString(CryptoJS.enc.Hex);
            } catch (e) {
                return "Error generating random key: " + e.message;
            }
        }

        isValidAESCiphertext(args) {
            if (typeof CryptoJS === "undefined") return false;
            try {
                return (typeof args.TEXT === "string" && args.TEXT.indexOf("U2FsdGVkX1") === 0);
            } catch (e) {
                return false;
            }
        }
    }

    Scratch.extensions.register(new EncryptionExtension());
})(Scratch);
