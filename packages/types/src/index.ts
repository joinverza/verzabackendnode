export type ErrorResponse = {
  error: {
    code: string;
    message: string;
    details: Record<string, unknown>;
    request_id: string;
  };
};

export type OkStatusResponse = { status: "ok" };

export type User = {
  id: string;
  email: string;
  name: string;
  phone: string;
  bio: string;
  avatar_url: string;
  did: string;
  role: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Session = {
  id: string;
  user_id: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  user_agent: string;
  ip: string;
};

export type AuthResponse = {
  user: { id: string };
  access_token: string;
  refresh_token: string;
};

