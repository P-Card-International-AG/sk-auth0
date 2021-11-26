import { expiresAtCookieName, providerCookieName } from '../cookies';
import { isSessionExpired } from '../helpers';
import Cookies from 'js-cookie';
import { signIn } from '.';

let runningRefresh: Promise<Response> | null = null;

// TODO: Ensure only one refresh is happening at a time
export async function ensureTokenRefreshed(
	fetch: (input: RequestInfo, init?: RequestInit) => Promise<Response>,
	isBrowser: boolean
): Promise<void> {
	if (!isBrowser) {
		return;
	}

	if (runningRefresh != null) {
		await runningRefresh;
		return;
	}

	const expiresAtString = Cookies.get(expiresAtCookieName);
	const provider = Cookies.get(providerCookieName);
	if (expiresAtString == null || provider == null) {
		return;
	}

	const expiresAtSeconds = parseInt(expiresAtString, 10);
	if (isNaN(expiresAtSeconds)) {
		return;
	}
	if (isSessionExpired(expiresAtSeconds)) {
		runningRefresh = fetch(`/api/auth/refresh/${provider}`, { method: 'POST' });
		const response = await runningRefresh;
		runningRefresh = null;
		if (response.status === 403) {
			signIn(provider);
		} else if (!response.ok) {
			throw new Error('Something went wrong while refreshing token!');
		}
	}
}
