const WebSocket = require('ws');
const crypto = require('crypto');

const ws = new WebSocket('ws://localhost:8080');

const ivHex = 'abcdefabcdefabcdefabcdefabcdefab';
const iv = Buffer.from(ivHex, 'hex');

let sharedSecret;
let sessionId;
let clientDH;

ws.on('open', () => {
    console.log('Připojeno k serveru');
});

ws.on('message', (data) => {
    const obj = JSON.parse(data);

    if (obj.prime && obj.generator && obj.pubKey) {
        clientDH = crypto.createDiffieHellman(obj.prime, 'hex', obj.generator, 'hex');
        const clientPubKey = clientDH.generateKeys();

        const rawSecret = clientDH.computeSecret(Buffer.from(obj.pubKey, 'hex'));

        sharedSecret = crypto.createHash('sha256').update(rawSecret).digest();

        ws.send(JSON.stringify({
            pubKey: clientPubKey.toString('hex')
        }));
    } 
    else if (obj.sessionInit) {
        sessionId = obj.sessionInit;
        sendEncryptedJson({
            message: "Test po navázání spojení."
        });
    } 
    else {
        console.log("Zpráva od serveru:", getDecryptedJson(obj));
    }
});


const getDecryptedJson = (data) => {
    if (!sharedSecret) {
        return sendJson(ws, { error: "Neplatná session" });
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', sharedSecret, iv);
    let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    const decryptedJson = JSON.parse(decrypted);

    return decryptedJson;
}

const sendEncryptedJson = (json) => {
    try {
        if (!sharedSecret) {
            throw new Error('sharedSecret není definován');
        }

        const cipher = crypto.createCipheriv('aes-256-cbc', sharedSecret, iv);
        let encrypted = cipher.update(JSON.stringify(json), 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const message = {
            session: sessionId,
            encrypted
        };

        ws.send(JSON.stringify(message));
    } catch (err) {
        console.error("Chyba při šifrování/odesílání:", err.message);
    }
};

