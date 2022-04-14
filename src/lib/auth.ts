import type { RequestHandler } from '@sveltejs/kit';
import type { Body, EndpointOutput, Fallthrough } from '@sveltejs/kit/types/endpoint';
import type { Either } from '@sveltejs/kit/types/helper';
import type { Handle, RequestEvent } from '@sveltejs/kit/types/hooks';
import cookie from 'cookie';
import * as cookies from './cookies.js';
import { RefreshTokenExpiredError } from './errors.js';
import { isSessionExpired } from './helpers.js';
import { join } from './path.js';

// This hack is needed because vite currently has a bug where it cannot resolve imports as keys in object destructuring assignments.
const { expiresAtCookieName, accessTokenCookieName, refreshTokenCookieName } = cookies;

interface Config {
	/**
	 * The domain of your auth0 application. For example: dev-gx493my5.eu.auth0.com
	 */
	auth0Domain: string;
	/**
	 * The Client ID of your auth0 application.
	 */
	clientId: string;
	/**
	 * The Client Secret of your auth0 application.
	 */
	clientSecret: string;
	/**
	 * The Identifier of your auth0 API.
	 */
	audience: string;
	/**
	 * The max age of the cookies that are set.
	 */
	maxAge: number;
	/**
	 * The domain of your website. This has to be set if the cookie should be sent to subdomains.
	 */
	domain?: string;
	/**
	 * The path of your api proxy. The library will pass the access token in the locals.accessToken field on the request.
	 */
	apiProxyPath?: string;
	/**
	 * Any extra scopes you want to pass to the auth0 /authorize call.
	 */
	extraScopes?: string[];
}

interface TokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in: number;
	token_type: string;
}

const basePath = '/api/auth';
const sameSiteConfig = 'lax';
const secureConfig = true;

export class Auth {
	// private readonly config: AuthConfig & InternalConfig;
	private readonly config: Config;

	constructor(config: PartialBy<Config, 'maxAge'>) {
		this.config = {
			maxAge: 60 * 60 * 24 * 30, // 30 days
			...config
		};
	}

	public isSignedIn({ request: { headers } }: RequestEvent): boolean {
		const { [accessTokenCookieName]: accessToken } = cookie.parse(headers.get('cookie') ?? '');

		return accessToken != null;
	}

	public getUrl(path: string, url: URL): string {
		const pathname = this.getPath(path);
		return new URL(pathname, this.getBaseUrl(url)).href;
	}

	public handle: Handle = ({ event, resolve }) => {
		const request = event.request;
		const path = event.url.pathname;
		if (this.config.apiProxyPath && path.startsWith(this.config.apiProxyPath)) {
			event.locals.accessToken = this.getAccessTokenCookie(request);
		} else if (!path.startsWith('/api/auth/refresh')) {
			const expiresAt = this.getExpiresAtCookie(request);
			if (expiresAt != null && isSessionExpired(expiresAt)) {
				return new Response(null, {
					status: 302,
					headers: {
						Location: `/api/auth/refresh?redirect=${
							path +
							([...event.url.searchParams].length > 0
								? '?' + event.url.searchParams.toString()
								: '')
						}`
					}
				});
			}
		}

		return resolve(event);
	};

	private getAccessTokenCookie({ headers }: Request): string | null {
		const { [accessTokenCookieName]: accessToken } = cookie.parse(headers.get('cookie') ?? '');
		return accessToken;
	}

	private getExpiresAtCookie({ headers }: Request): number | null {
		const { [expiresAtCookieName]: expiresAtString } = cookie.parse(headers.get('cookie') ?? '');
		if (expiresAtString == null) {
			return null;
		}

		const expiresAtSeconds = parseInt(expiresAtString, 10);
		if (isNaN(expiresAtSeconds)) {
			return null;
		}

		return expiresAtSeconds;
	}

	private getBaseUrl(url: URL): string {
		return `${url.protocol}//${url.host}`;
	}

	private getPath(path: string): string {
		const pathname = join([basePath, path]);
		return pathname;
	}

	private async getRedirectUrl(redirectUrl?: string): Promise<string> {
		const redirect = redirectUrl ?? '/';
		return redirect;
	}

	private async handleEndpoint(
		event: RequestEvent
	): Promise<Either<EndpointOutput<Body>, Fallthrough>> {
		const path = event.url.pathname;

		if (path === this.getPath('signout')) {
			return await this.handleSignout(event);
		}

		const regex = new RegExp(join([basePath, `(?<method>signin|refresh|callback)`]));
		const match = path.match(regex);

		if (match && match.groups) {
			if (match.groups.method === 'signin') {
				return await this.handleSignin(event);
			} else if (match.groups.method === 'refresh') {
				return await this.handleRefresh(event);
			} else {
				return await this.handleCallback(event);
			}
		}

		return {
			status: 404,
			body: 'Not found.'
		};
	}

	private async handleSignin(event: RequestEvent): Promise<EndpointOutput> {
		const { searchParams } = event.url;
		const state = [`redirect=${searchParams.get('redirect') ?? this.getUrl('/', event.url)}`].join(
			','
		);
		let base64State;
		if (typeof Buffer !== 'undefined') {
			base64State = Buffer.from(state).toString('base64');
		} else base64State = btoa(state);
		const nonce = Math.round(Math.random() * 1000).toString(); // TODO: Generate random based on user values
		const url = this.getAuthorizationUrl(event, base64State, nonce);

		if (event.request.method === 'POST') {
			return {
				body: {
					redirect: url
				}
			};
		}

		return {
			status: 302,
			headers: {
				Location: url
			}
		};
	}

	private getAuthorizationUrl(event: RequestEvent, state: string, nonce: string): string {
		const data = {
			state,
			nonce,
			response_type: 'code',
			client_id: this.config.clientId,
			audience: this.config.audience,
			scope: ['offline_access', ...(this.config.extraScopes ?? [])].join(' '),
			redirect_uri: this.getCallbackUri(event.url)
		};

		const url = `https://${this.config.auth0Domain}/authorize?${new URLSearchParams(data)}`;
		return url;
	}

	private async handleSignout(event: RequestEvent): Promise<EndpointOutput> {
		const headers = new Headers();
		for (const cookie of this.getDeleteCookieHeaders()) {
			headers.append('set-cookie', cookie);
		}

		if (event.request.method === 'POST') {
			return {
				headers,
				body: {
					signout: true
				}
			};
		}

		const redirect = await this.getRedirectUrl(event.url.searchParams.get('redirect') ?? undefined);
		headers.append('Location', redirect);
		return {
			status: 302,
			headers
		};
	}

	private async handleCallback(event: RequestEvent): Promise<EndpointOutput> {
		const { searchParams } = event.url;
		const code = searchParams.get('code');
		if (code == null) {
			throw new Error('Code not provided');
		}

		const redirectUrl = getStateValue(searchParams, 'redirect');

		const tokens = await this.getTokens(code, this.getCallbackUri(event.url));
		const accessToken = tokens.access_token;
		const refreshToken = tokens.refresh_token;
		const expiresAt = getExpirationFromToken(tokens.access_token);

		const redirect = await this.getRedirectUrl(redirectUrl);

		const headers = new Headers();
		headers.append('Location', redirect);
		for (const cookie of this.getSetCookieHeaders(accessToken, refreshToken, expiresAt)) {
			headers.append('set-cookie', cookie);
		}

		return {
			status: 302,
			headers
		};
	}

	private getCallbackUri(url: URL): string {
		return this.getUrl('/callback', url);
	}

	private async getTokens(code: string, redirectUri: string): Promise<TokenResponse> {
		const data: Record<string, string> = {
			code,
			grant_type: 'authorization_code',
			client_id: this.config.clientId,
			client_secret: this.config.clientSecret,
			redirect_uri: redirectUri
		};

		const body = JSON.stringify(data);

		const res = await fetch(`https://${this.config.auth0Domain}/oauth/token`, {
			body,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			}
		});

		return await res.json();
	}

	private async handleRefresh(event: RequestEvent): Promise<EndpointOutput> {
		const { searchParams } = event.url;
		const { [refreshTokenCookieName]: oldRefreshToken } = cookie.parse(
			event.request.headers.get('cookie')
		);
		try {
			const tokens = await this.getTokensForRefresh(oldRefreshToken);
			const newAccessToken = tokens.access_token;
			const newRefreshToken = tokens.refresh_token;
			const expiresAt = getExpirationFromToken(newAccessToken);

			const headers = new Headers();
			for (const cookie of this.getSetCookieHeaders(newAccessToken, newRefreshToken, expiresAt)) {
				headers.append('set-cookie', cookie);
			}

			if (event.request.method === 'GET') {
				const redirect = await this.getRedirectUrl(searchParams.get('redirect') ?? undefined);
				headers.append('Location', redirect);
				return {
					status: 302,
					headers
				};
			} else {
				return {
					status: 200,
					headers
				};
			}
		} catch (error) {
			if (error instanceof RefreshTokenExpiredError) {
				const headers = new Headers();
				for (const cookie of this.getDeleteCookieHeaders()) {
					headers.append('set-cookie', cookie);
				}

				if (event.request.method === 'GET') {
					const redirect = await this.getRedirectUrl(searchParams.get('redirect') ?? undefined);
					headers.append('Location', redirect);
					return {
						status: 302,
						headers
					};
				} else {
					return {
						status: 403,
						headers
					};
				}
			} else {
				throw error;
			}
		}
	}

	private async getTokensForRefresh(refreshToken: string): Promise<TokenResponse> {
		const data: Record<string, string> = {
			grant_type: 'refresh_token',
			client_id: this.config.clientId,
			client_secret: this.config.clientSecret,
			refresh_token: refreshToken
		};

		const body = JSON.stringify(data);

		const res = await fetch(`https://${this.config.auth0Domain}/oauth/token`, {
			body,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			}
		});

		if (res.status === 403) {
			throw new RefreshTokenExpiredError();
		}
		if (!res.ok) {
			throw new Error('Something went wrong while refreshing the tokens: ' + (await res.text()));
		}

		return await res.json();
	}

	get: RequestHandler = async (event) => {
		return await this.handleEndpoint(event);
	};

	post: RequestHandler = async (request) => {
		return await this.handleEndpoint(request);
	};

	private getSetCookieHeaders(
		accessToken: string,
		refreshToken: string | undefined,
		expiresAt: number
	): string[] {
		const cookies = [
			cookie.serialize(accessTokenCookieName, accessToken, this.getAccessTokenCookieSettings()),
			cookie.serialize(expiresAtCookieName, expiresAt.toString(), this.getExpiresAtCookieSettings())
		];

		if (refreshToken != null) {
			cookies.push(
				cookie.serialize(refreshTokenCookieName, refreshToken, {
					...this.getRefreshTokenCookieSettings()
				})
			);
		}

		return cookies;
	}

	private getDeleteCookieHeaders() {
		return [
			cookie.serialize(accessTokenCookieName, '', {
				...this.getAccessTokenCookieSettings(),
				maxAge: undefined,
				expires: new Date(1970, 1, 1, 0, 0, 0, 0)
			}),
			cookie.serialize(refreshTokenCookieName, '', {
				...this.getRefreshTokenCookieSettings(),
				maxAge: undefined,
				expires: new Date(1970, 1, 1, 0, 0, 0, 0)
			}),
			cookie.serialize(expiresAtCookieName, '', {
				...this.getExpiresAtCookieSettings(),
				maxAge: undefined,
				expires: new Date(1970, 1, 1, 0, 0, 0, 0)
			})
		];
	}

	private getAccessTokenCookieSettings(): cookie.CookieSerializeOptions {
		return {
			httpOnly: true,
			path: '/',
			sameSite: sameSiteConfig,
			secure: secureConfig,
			maxAge: this.config.maxAge,
			...(this.config.domain ? { domain: this.config.domain } : {})
		};
	}

	private getRefreshTokenCookieSettings(): cookie.CookieSerializeOptions {
		return {
			path: basePath,
			httpOnly: true,
			sameSite: sameSiteConfig,
			secure: secureConfig,
			maxAge: this.config.maxAge,
			...(this.config.domain ? { domain: this.config.domain } : {})
		};
	}

	private getExpiresAtCookieSettings(): cookie.CookieSerializeOptions {
		return {
			path: '/',
			sameSite: sameSiteConfig,
			secure: secureConfig,
			maxAge: this.config.maxAge,
			...(this.config.domain ? { domain: this.config.domain } : {})
		};
	}
}

function getExpirationFromToken(token: string): number {
	const [, payload] = token.split('.');
	let payloadBuffer;
	if (typeof Buffer !== 'undefined') payloadBuffer = Buffer.from(payload, 'base64');
	else payloadBuffer = atob(payload);
	const { exp } = JSON.parse(payloadBuffer.toString('utf-8'));

	if (exp == null) {
		throw new Error('exp claim must be specified');
	}

	return exp;
}

function getStateValue(query: URLSearchParams, name: string): string | undefined {
	const stateParam = query.get('state');
	if (stateParam) {
		let state;
		if (typeof Buffer !== 'undefined') state = Buffer.from(stateParam, 'base64');
		else state = atob(stateParam);
		return state
			.split(',')
			.find((state) => state.startsWith(`${name}=`))
			?.replace(`${name}=`, '');
	}
}

type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
