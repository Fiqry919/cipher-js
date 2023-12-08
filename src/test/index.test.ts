import crypto from 'crypto';
import Cipher from '../class/Cipher';

const getSizeBytes = (bytes: number, decimal: number = 2) => {
    if (!+bytes) return '0 Bytes';

    const size = 1024;
    const unit = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const frag = decimal < 0 ? 0 : decimal;
    const index = Math.floor(Math.log(bytes) / Math.log(size));

    return `${parseFloat((bytes / Math.pow(size, index)).toFixed(frag))} ${unit[index]}`
}

const secret_key = "hTuo8LczKzFBTRmvu6Q0kkI5EmDlgsAiylUigYnHjwsQ4jG2wpgKuhqJsoenlFrH";

const cipher = new Cipher({
    algorithm: 'chacha20-poly1305', // need fix when AES-CCM
    key: {
        password: secret_key,
        iteration: 100000,
        digest: 'sha256'
    },
    options: {
        authTagLength: 16
    },
    encoding: 'base64',
});

const data = { data: 'test' };
console.log('size:', getSizeBytes(new Blob([JSON.stringify(data)]).size));

console.time("encrypt_time");
const crypt = cipher.createCipher(data);
console.timeEnd("encrypt_time");
console.log('encrypt size:', getSizeBytes(new Blob([crypt]).size));

console.time("decrypt_time");
const decrypt = cipher.createDecipher(crypt);
console.timeEnd("decrypt_time");
console.log('decrypt size:', getSizeBytes(new Blob([JSON.stringify(decrypt)]).size));

