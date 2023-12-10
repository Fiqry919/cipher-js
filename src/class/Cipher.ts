import { Crypto, Options } from "../interfaces";

class CipherJs {
    private algorithm: string[] = [];

    private bytes: number;

    private counterMode: boolean = false;

    constructor(private op: Options) {
        this.algorithm = this.op.algorithm.split('-');
        this.bytes = (isNaN(parseInt(this.algorithm[1]))
            ? 256 : parseInt(this.algorithm[1])) / 8;
        this.counterMode = this.algorithm[2] === 'ccm'
            || this.algorithm[2] === 'ocb'
            || !this.algorithm[2];
    }

    /**
     * 
     */
    createCipher = <T = any>(object: T) => {
        let key: any = this.op.key;
        let salt = Crypto.randomBytes(16);
        let iv = this.op.iv;

        if (!iv) iv = Crypto.randomBytes(this.counterMode ? 12 : 16);

        if (typeof key !== 'string' && 'password' in key)
            key = Crypto.pbkdf2Sync(key.password, salt, key.iteration, this.bytes, key.digest);

        const cipher = Crypto.createCipheriv(this.op.algorithm, key, iv, this.op?.options);
        const encoding = this.op.encoding;

        let encrypted = cipher.update(JSON.stringify(object), 'utf8', encoding);
        encrypted += cipher.final(encoding);

        let tag: Buffer = Buffer.alloc(0);
        if (this.algorithm[2] !== 'cbc' && this.op.options?.authTagLength)
            tag = (<any>cipher).getAuthTag() as Buffer;

        const result = Buffer.concat([salt, <any>iv, tag, Buffer.from(encrypted, encoding)]);
        return result.toString(encoding);
    }

    /**
     * 
     */
    createDecipher = <T = any>(cipher: any): T => {
        const encoding = this.op.encoding;
        const buffer = Buffer.from(cipher, encoding);
        let key = this.op.key;
        let salt = buffer.subarray(0, 16);
        let iv = this.op.iv;

        if (!iv) iv = buffer.subarray(16, this.counterMode ? 28 : 32);

        if (typeof key !== 'string' && 'password' in key)
            key = Crypto.pbkdf2Sync(key.password, salt, key.iteration, this.bytes, key.digest);

        const decipher = Crypto.createDecipheriv(this.op.algorithm, key, iv, this.op?.options);
        let encrypted = buffer.subarray(this.counterMode ? 28 : 32);

        if (this.algorithm[2] !== 'cbc' && this.op.options?.authTagLength) {
            const length = this.op.options?.authTagLength as number;
            (<any>decipher).setAuthTag(encrypted.subarray(0, length))
            encrypted = encrypted.subarray(length);
        }

        let decrypted = decipher.update(encrypted.toString(encoding), encoding, 'utf8');
        decrypted += decipher.final('utf8');

        return JSON.parse(decrypted);
    }
}

export default CipherJs;