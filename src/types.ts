export type Profile = any;
export type CallbackResult = {
  idToken: string;
  refreshToken: string;
  redirectUrl?: string;
  expiresAt: number;
};
export type RefreshResult = { idToken: string; refreshToken: string; expiresAt: number };
