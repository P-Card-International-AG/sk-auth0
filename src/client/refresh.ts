import Cookies from "js-cookie";

export async function ensureTokenRefreshed(
  fetch: (input: RequestInfo, init?: RequestInit) => Promise<Response>,
  isBrowser: boolean
): Promise<void> {
  if (!isBrowser) {
    return;
  }

  const expiresAtString = Cookies.get("svelteauth_expires_at");
  const provider = Cookies.get("svelteauth_provider");
  if (expiresAtString == null || provider == null) {
    return;
  }

  const expiresAtSeconds = parseInt(expiresAtString, 10);
  if (isNaN(expiresAtSeconds)) {
    return;
  }
  const safeExpiresAtSeconds = expiresAtSeconds - 10 * 60;
  const expiresAt = new Date(safeExpiresAtSeconds * 1000);

  if (expiresAt < new Date()) {
    const response = await fetch(`/api/auth/signin/${provider}`);
    if (!response.ok) {
      throw new Error("Something went wrong while refreshing token!");
    }
  }
}
