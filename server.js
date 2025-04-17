const WebSocket = require('ws');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const ivHex = 'abcdefabcdefabcdefabcdefabcdefab';
const iv = Buffer.from(ivHex, 'hex');

const wss = new WebSocket.Server({ port: 8080 });

const sessionsAndSecrets = new Map();

const sendJson = (ws, json) => {
    ws.send(JSON.stringify(json));
}

wss.on('connection', (ws) => {
    console.log('Klient se připojil');

    const serverDH = crypto.createDiffieHellman(512);
    const serverPubKey = serverDH.generateKeys();

    sendJson(ws, {
        prime: serverDH.getPrime('hex'),
        generator: serverDH.getGenerator('hex'),
        pubKey: serverPubKey.toString('hex')
    });

    ws.on('message', (message) => {
        const data = JSON.parse(message);

        if (data.pubKey) {
            const clientPubKey = Buffer.from(data.pubKey, 'hex');
            let sharedSecret = serverDH.computeSecret(clientPubKey);
            sharedSecret = crypto.createHash('sha256').update(sharedSecret).digest();
            const sessionId = uuidv4();

            sessionsAndSecrets.set(sessionId, sharedSecret);
            sendJson(ws, {
                sessionInit: sessionId
            });
        } else {

            console.log("Dešifrovaná zpráva:", getDecryptedJson(ws, data));
            sendEncryptedJson(ws, data.session,  { message: "ahoj" });
        }
    });
});

const getDecryptedJson = (ws, data) => {
    const sharedSecret = sessionsAndSecrets.get(data.session);

    if (!sharedSecret) {
        return sendJson(ws, { error: "Neplatná session" });
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', sharedSecret, iv);
    let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    const decryptedJson = JSON.parse(decrypted);

    return decryptedJson;
}

const sendEncryptedJson = (ws, sessionId, json, ) => {

    const sharedSecret = sessionsAndSecrets.get(sessionId);

    if (!sharedSecret) {
        console.log(sessionsAndSecrets);
        console.log("neplatna session:" + sessionId);
        return;
    }

    try {
        if (!sharedSecret) {
            throw new Error('sharedSecret není definován');
        }

        const cipher = crypto.createCipheriv('aes-256-cbc', sharedSecret, iv);
        let encrypted = cipher.update(JSON.stringify(json), 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const message = {
            encrypted
        };

        ws.send(JSON.stringify(message));
    } catch (err) {
        console.error("Chyba při šifrování/odesílání:", err.message);
    }
};


