"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const interfaces_1 = require("../interfaces");
class CipherJs {
    constructor(op) {
        this.op = op;
        this.algorithm = [];
        this.counterMode = false;
        /**
         *
         */
        this.createCipher = (object) => {
            var _a, _b;
            let key = this.op.key;
            let salt = interfaces_1.Crypto.randomBytes(16);
            let iv = this.op.iv;
            if (!iv)
                iv = interfaces_1.Crypto.randomBytes(this.counterMode ? 12 : 16);
            if (typeof key !== 'string' && 'password' in key)
                key = interfaces_1.Crypto.pbkdf2Sync(key.password, salt, key.iteration, this.bytes, key.digest);
            const cipher = interfaces_1.Crypto.createCipheriv(this.op.algorithm, key, iv, (_a = this.op) === null || _a === void 0 ? void 0 : _a.options);
            const encoding = this.op.encoding;
            let encrypted = cipher.update(JSON.stringify(object), 'utf8', encoding);
            encrypted += cipher.final(encoding);
            let tag = Buffer.alloc(0);
            if (this.algorithm[2] !== 'cbc' && ((_b = this.op.options) === null || _b === void 0 ? void 0 : _b.authTagLength))
                tag = cipher.getAuthTag();
            const result = Buffer.concat([salt, iv, tag, Buffer.from(encrypted, encoding)]);
            return result.toString(encoding);
        };
        /**
         *
         */
        this.createDecipher = (cipher) => {
            var _a, _b, _c;
            const encoding = this.op.encoding;
            const buffer = Buffer.from(cipher, encoding);
            let key = this.op.key;
            let salt = buffer.subarray(0, 16);
            let iv = this.op.iv;
            if (!iv)
                iv = buffer.subarray(16, this.counterMode ? 28 : 32);
            if (typeof key !== 'string' && 'password' in key)
                key = interfaces_1.Crypto.pbkdf2Sync(key.password, salt, key.iteration, this.bytes, key.digest);
            const decipher = interfaces_1.Crypto.createDecipheriv(this.op.algorithm, key, iv, (_a = this.op) === null || _a === void 0 ? void 0 : _a.options);
            let encrypted = buffer.subarray(this.counterMode ? 28 : 32);
            if (this.algorithm[2] !== 'cbc' && ((_b = this.op.options) === null || _b === void 0 ? void 0 : _b.authTagLength)) {
                const length = (_c = this.op.options) === null || _c === void 0 ? void 0 : _c.authTagLength;
                decipher.setAuthTag(encrypted.subarray(0, length));
                encrypted = encrypted.subarray(length);
            }
            let decrypted = decipher.update(encrypted.toString(encoding), encoding, 'utf8');
            decrypted += decipher.final('utf8');
            return JSON.parse(decrypted);
        };
        this.algorithm = this.op.algorithm.split('-');
        this.bytes = (isNaN(parseInt(this.algorithm[1]))
            ? 256 : parseInt(this.algorithm[1])) / 8;
        this.counterMode = this.algorithm[2] === 'ccm'
            || this.algorithm[2] === 'ocb'
            || !this.algorithm[2];
    }
}
exports.default = CipherJs;
