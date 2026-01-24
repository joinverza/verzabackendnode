export declare function sha256Hex(input: string | Buffer): string;
export declare function hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer<ArrayBuffer>;
export declare function encryptJson(opts: {
    masterKeyB64: string;
    plaintext: unknown;
}): string;
export declare function decryptJson(opts: {
    masterKeyB64: string;
    ciphertextB64: string;
}): unknown;
export declare function canonicalJson(value: unknown): string;
export declare function signReceipt(opts: {
    seedB64: string;
    receipt: unknown;
}): {
    sig_kid: string;
    sig_b64: string;
};
export declare function verifyDidSignedRequest(opts: {
    method: string;
    path: string;
    timestamp: string;
    nonce: string;
    rawBody: Buffer;
    did: string;
    signature: string;
}): boolean;
//# sourceMappingURL=index.d.ts.map