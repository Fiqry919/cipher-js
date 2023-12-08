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
    createCipher: (object: any) => string;
    /**
     *
     */
    createDecipher: <T = any>(cipher: string) => T;
}
export default CipherJs;
