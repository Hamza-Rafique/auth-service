export interface User {
  id: string; // UUID
  email: string;
  password_hash: string;
  is_active: boolean;
  email_verified: boolean;
  created_at: Date;
  updated_at: Date;
}

// Use a Pick or Omit type for creating new users
export type CreateUserInput = Omit<User, 'id' | 'created_at' | 'updated_at'>;