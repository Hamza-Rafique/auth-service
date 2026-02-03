export interface User {
    id: string;
    email: string;
    password_hash: string;
    is_active: boolean;
    email_verified: boolean;
    created_at: Date;
    updated_at: Date;
}
export type CreateUserInput = Omit<User, 'id' | 'created_at' | 'updated_at'>;
//# sourceMappingURL=index.d.ts.map