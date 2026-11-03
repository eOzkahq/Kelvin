export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  organizationId: string;
}

export interface AuthSession {
  token: string;
  user: User;
  expiresAt: string;
}
