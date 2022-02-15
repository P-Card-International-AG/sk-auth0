import { expiresAtCookieName } from '../cookies.js';
import { isSessionExpired } from '../helpers.js';
import { signIn } from './signIn.js';
import Cookies from 'js-cookie';

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
	if (expiresAtString == null) {
		return;
	}

	const expiresAtSeconds = parseInt(expiresAtString, 10);
	if (isNaN(expiresAtSeconds)) {
		return;
	}
	if (isSessionExpired(expiresAtSeconds)) {
		runningRefresh = fetch(`/api/auth/refresh`, { method: 'POST' });
		const response = await runningRefresh;
		runningRefresh = null;
		if (response.status === 403) {
			signIn();
		} else if (!response.ok) {
			throw new Error('Something went wrong while refreshing token!');
		}
	}
}
