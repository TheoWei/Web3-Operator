
const crypto = require('crypto');
class Crypto{
    static getRandom = (_size) => {
        const buf = crypto.randomBytes(_size);
        console.log('random key hex string:: ', buf.toString('hex'));
        return buf;
    }

    static getKeyPairs = (_passphrase) => {
        return crypto.generateKeyPairSync('ec', {
            namedCurve: 'B-163',
            publicKeyEncoding: {
                type: 'spki',
                format: 'der'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der',
                cipher: 'aes-128-cbc',
                passphrase: _passphrase
            }
        })
    }

    static md5_hash = (_data) => {
        let res = crypto.createHash('md5').update(_data).digest('hex');
        console.log('md5 hash:: ', res);
        return res;
    }

    static getSharedSecret = (_privateKey1, _privateKey2) => { // private key length = 32
        let ecdh = crypto.createECDH('secp256k1'),
            ecdh2 = crypto.createECDH('secp256k1');

        ecdh.setPrivateKey(_privateKey1);
        ecdh2.setPrivateKey(_privateKey2);
        let key2 = ecdh2.getPublicKey('hex')

        let secret = ecdh.computeSecret(key2, 'hex');
        console.log('secret hex string ::  ', secret.toString('hex'));
        return secret;
    }


    static Crypto = (_data, _key, exec) => { // key length = 32 byte

        const algorithm = 'aes-256-cbc', //aes256、aes128
            key = _key.slice(0, 32),
            iv = crypto.randomBytes(16);

        if (exec == 'encrypt') {
            let enc_data = encrypt(JSON.stringify(_data));
            return enc_data;
        } else if (exec == 'decrypt') {
            let dec_data = decrypt(_data);
            return dec_data;
        } else {
            return new Error('crypt process failed!');
        }

        function encrypt(data) {
            try {
                let cipher = crypto.createCipheriv(algorithm, key, iv),
                    encrypted = cipher.update(data);
                encrypted = Buffer.concat([encrypted, cipher.final()]);
                console.log('encrypted! ');
                return { key: key.toString('hex'), iv: iv.toString('hex'), enc_data: encrypted.toString('hex') };
            } catch (err) {
                return new Error('encrypt failed!');
            }
        }
        function decrypt(data) {
            try {
                let dec_iv = Buffer.from(data.iv, 'hex'),
                    dec_key = data.key.slice(0, 32),
                    _encryptedData = Buffer.from(data.enc_data, 'hex');

                let decipher = crypto.createDecipheriv(algorithm, dec_key, dec_iv),
                    decrypted = decipher.update(_encryptedData);

                decrypted = Buffer.concat([decrypted, decipher.final()]);
                console.log('decrypted!');
                return decrypted;
            } catch (err) {
                return new Error('decrypt failed!');
            }
        }
    }
}

module.exports = Crypto;




