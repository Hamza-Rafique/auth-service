"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptionService = exports.EncryptionService = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const argon2 = __importStar(require("argon2"));
const crypto_1 = __importDefault(require("crypto"));
class EncryptionService {
    bcryptSaltRounds;
    constructor() {
        this.bcryptSaltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12');
    }
    async hashPassword(password) {
        try {
            return await argon2.hash(password, {
                type: argon2.argon2id,
                memoryCost: 2 ** 16,
                timeCost: 3,
                parallelism: 1,
            });
        }
        catch (error) {
            return this.hashWithBcrypt(password);
        }
    }
    async hashWithBcrypt(password) {
        return bcrypt_1.default.hash(password, this.bcryptSaltRounds);
    }
    async verifyPassword(hashedPassword, plainPassword) {
        try {
            if (hashedPassword.startsWith('$argon2')) {
                return await argon2.verify(hashedPassword, plainPassword);
            }
            return bcrypt_1.default.compare(plainPassword, hashedPassword);
        }
        catch (error) {
            throw new Error('Password verification failed');
        }
    }
    generateRandomToken(length = 32) {
        return crypto_1.default.randomBytes(length).toString('hex');
    }
    timingSafeEqual(a, b) {
        try {
            return crypto_1.default.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
        }
        catch {
            return false;
        }
    }
    generateSecureRandomBytes(size) {
        return crypto_1.default.randomBytes(size);
    }
}
exports.EncryptionService = EncryptionService;
exports.encryptionService = new EncryptionService();
//# sourceMappingURL=encryption.js.map