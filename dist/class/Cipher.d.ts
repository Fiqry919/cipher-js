import { Options } from "../interfaces";
declare class CipherJs {
    private op;
    private algorithm;
    private bytes;
    private counterMode;
    constructor(op: Options);
    /**
     *
     */
    createCipher: <T = any>(object: T) => string;
    /**
     *
     */
    createDecipher: <T = any>(cipher: any) => T;
}
export default CipherJs;
