import Crypto from 'crypto';
import { TransformOptions } from 'stream';
import { BinaryLike, CipherKey, Encoding } from 'crypto';

/**
 * 
 */
export type TypeCBC = "aes-128-cbc" | "aes-192-cbc" | "aes-256-cbc";
/**
 * 
 */
export type TypeCCM = /*"aes-128-ccm" | "aes-192-ccm" | "aes-256-ccm" |*/ "chacha20-poly1305";
/**
 * 
 */
export type TypeGCM = "aes-128-gcm" | "aes-192-gcm" | "aes-256-gcm";
/**
 * 
 */
export type TypeOCB = "aes-128-ocb" | "aes-192-ocb" | "aes-256-ocb";
/**
 * 
 */
export type DigestAlgorithm = "sha1" | "sha224" | "sha256" | "sha384" | "sha512" | "md5";
/**
 * 
 */
export type Algorithm = TypeCBC | TypeCCM | TypeGCM | TypeOCB;
/**
 * Password-Based Key Derivation Function 2 (PBKDF2) implementation. 
 * A selected HMAC digest algorithm specified by `digest` is applied to derive 
 * a key of the requested byte length (`keylen`) from the`password`, `salt` and `iterations`.
 */
export interface Pbkdf2Options {
    /**
     * 
     */
    password: string
    /**
     * 
     */
    iteration: number
    /**
     * 
     */
    digest: DigestAlgorithm
}

export interface StreamOptions extends TransformOptions {
    /**
     * 
     */
    authTagLength: number
}

export interface Options {
    /**
     * 
     */
    algorithm: Algorithm
    /**
     * 
     */
    key: CipherKey | Pbkdf2Options
    /**
     * 
     */
    iv?: BinaryLike
    /**
     * 
     */
    options?: Partial<StreamOptions>
    /**
     * 
     */
    encoding: Encoding
}

export { Crypto }