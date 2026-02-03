"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizer = exports.Sanitizer = void 0;
const sanitize_html_1 = __importDefault(require("sanitize-html"));
class Sanitizer {
    htmlSanitizeOptions = {
        allowedTags: [],
        allowedAttributes: {},
    };
    deepSanitize(obj) {
        if (!obj || typeof obj !== 'object')
            return obj;
        if (Array.isArray(obj)) {
            return obj.map(item => this.deepSanitize(item));
        }
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                sanitized[key] = this.sanitizeString(value);
            }
            else if (typeof value === 'object' && value !== null) {
                sanitized[key] = this.deepSanitize(value);
            }
            else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }
    sanitizeString(input) {
        if (!input)
            return input;
        let sanitized = input.trim();
        sanitized = sanitized.replace(/\0/g, '');
        sanitized = (0, sanitize_html_1.default)(sanitized, this.htmlSanitizeOptions);
        sanitized = sanitized.replace(/\s+/g, ' ');
        return sanitized;
    }
    sanitizeEmail(email) {
        const sanitized = this.sanitizeString(email).toLowerCase();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(sanitized)) {
            throw new Error('Invalid email format');
        }
        return sanitized;
    }
    containsSQLInjection(input) {
        const sqlKeywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION',
            'OR', 'AND', 'WHERE', 'FROM', 'TABLE', 'DATABASE'
        ];
        const upperInput = input.toUpperCase();
        return sqlKeywords.some(keyword => upperInput.includes(keyword) &&
            /[=\s]/.test(upperInput.charAt(upperInput.indexOf(keyword) - 1)));
    }
    sanitizeRequest = (req, res, next) => {
        if (req.body) {
            req.body = this.deepSanitize(req.body);
        }
        if (req.query) {
            req.query = this.deepSanitize(req.query);
        }
        if (req.params) {
            req.params = this.deepSanitize(req.params);
        }
        next();
    };
}
exports.Sanitizer = Sanitizer;
exports.sanitizer = new Sanitizer();
//# sourceMappingURL=sanitizer.js.map