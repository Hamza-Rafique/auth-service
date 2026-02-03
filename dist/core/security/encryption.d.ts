export declare class EncryptionService {
    private readonly bcryptSaltRounds;
    constructor();
    hashPassword(password: string): Promise<string>;
    hashWithBcrypt(password: string): Promise<string>;
    verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean>;
    generateRandomToken(length?: number): string;
    timingSafeEqual(a: string, b: string): boolean;
    generateSecureRandomBytes(size: number): Buffer;
}
export declare const encryptionService: EncryptionService;
//# sourceMappingURL=encryption.d.ts.map