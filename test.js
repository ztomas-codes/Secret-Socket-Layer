const crypto = require('crypto');

// Alice
const alice = crypto.createDiffieHellman(512);
const aliceKey = alice.generateKeys().toString("hex");

// Bob
const bob = crypto.createDiffieHellman(alice.getPrime().toString('hex'), alice.getGenerator().toString('hex'));
const bobKey = bob.generateKeys().toString("hex");

// Výměna klíčů
const aliceSecret = alice.computeSecret(bobKey);
const bobSecret = bob.computeSecret(aliceKey);

console.log('Alice Secret:', aliceSecret.toString('hex'));
console.log('Bob Secret: ', bobSecret.toString('hex'));
console.log('Shodují se?', aliceSecret.equals(bobSecret));

