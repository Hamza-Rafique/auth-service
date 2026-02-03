import { Request, Response, NextFunction } from 'express';
export declare class Sanitizer {
    private htmlSanitizeOptions;
    deepSanitize<T>(obj: T): T;
    sanitizeString(input: string): string;
    sanitizeEmail(email: string): string;
    containsSQLInjection(input: string): boolean;
    sanitizeRequest: (req: Request, res: Response, next: NextFunction) => void;
}
export declare const sanitizer: Sanitizer;
//# sourceMappingURL=sanitizer.d.ts.map