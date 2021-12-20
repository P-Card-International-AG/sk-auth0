import type { RequestHandler } from '@sveltejs/kit';
import type { EndpointOutput } from '@sveltejs/kit/types/endpoint';
import type { Handle, ServerRequest } from '@sveltejs/kit/types/hooks';
import { join } from './path';
import cookie from 'cookie';
import { isSessionExpired } from './helpers';
import * as cookies from './cookies';
import { RefreshTokenExpiredError } from './errors';

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

	public isSignedIn({ headers }: ServerRequest): boolean {
		const { [accessTokenCookieName]: accessToken } = cookie.parse(headers.cookie ?? '');

		return accessToken != null;
	}

	public getUrl(path: string, host: string): string {
		const pathname = this.getPath(path);
		return new URL(pathname, this.getBaseUrl(host)).href;
	}

	public handle: Handle = ({ request, resolve }) => {
		if (this.config.apiProxyPath && request.path.startsWith(this.config.apiProxyPath)) {
			request.locals.accessToken = this.getAccessTokenCookie(request);
		} else if (!request.path.startsWith('/api/auth/refresh')) {
			const expiresAt = this.getExpiresAtCookie(request);
			if (expiresAt != null && isSessionExpired(expiresAt)) {
				return {
					status: 302,
					headers: {
						Location: `/api/auth/refresh?redirect=${
							request.path + ([...request.query].length > 0 ? '?' + request.query.toString() : '')
						}`
					}
				};
			}
		}

		return resolve(request);
	};

	private getAccessTokenCookie({ headers }: ServerRequest): string | null {
		const { [accessTokenCookieName]: accessToken } = cookie.parse(headers.cookie ?? '');
		return accessToken;
	}

	private getExpiresAtCookie({ headers }: ServerRequest): number | null {
		const { [expiresAtCookieName]: expiresAtString } = cookie.parse(headers.cookie ?? '');
		if (expiresAtString == null) {
			return null;
		}

		const expiresAtSeconds = parseInt(expiresAtString, 10);
		if (isNaN(expiresAtSeconds)) {
			return null;
		}

		return expiresAtSeconds;
	}

	private getBaseUrl(host: string): string {
		return `http://${host}`;
	}

	private getPath(path: string): string {
		const pathname = join([basePath, path]);
		return pathname;
	}

	private async getRedirectUrl(redirectUrl?: string): Promise<string> {
		const redirect = redirectUrl ?? '/';
		return redirect;
	}

	private async handleEndpoint(request: ServerRequest): Promise<EndpointOutput> {
		const { path } = request;

		if (path === this.getPath('signout')) {
			return await this.handleSignout(request);
		}

		const regex = new RegExp(join([basePath, `(?<method>signin|refresh|callback)`]));
		const match = path.match(regex);

		if (match && match.groups) {
			if (match.groups.method === 'signin') {
				return await this.handleSignin(request);
			} else if (match.groups.method === 'refresh') {
				return await this.handleRefresh(request);
			} else {
				return await this.handleCallback(request);
			}
		}

		return {
			status: 404,
			body: 'Not found.'
		};
	}

	private async handleSignin(request: ServerRequest): Promise<EndpointOutput> {
		const { method, host, query } = request;
		const state = [`redirect=${query.get('redirect') ?? this.getUrl('/', host)}`].join(',');
		const base64State = Buffer.from(state).toString('base64');
		const nonce = Math.round(Math.random() * 1000).toString(); // TODO: Generate random based on user values
		const url = this.getAuthorizationUrl(request, base64State, nonce);

		if (method === 'POST') {
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

	private getAuthorizationUrl({ host }: ServerRequest, state: string, nonce: string): string {
		const data = {
			state,
			nonce,
			response_type: 'code',
			client_id: this.config.clientId,
			audience: this.config.audience,
			scope: ['offline_access', ...(this.config.extraScopes ?? [])].join(' '),
			redirect_uri: this.getCallbackUri(host)
		};

		const url = `https://${this.config.auth0Domain}/authorize?${new URLSearchParams(data)}`;
		return url;
	}

	private async handleSignout(request: ServerRequest): Promise<EndpointOutput> {
		const { method } = request;
		if (method === 'POST') {
			return {
				headers: {
					'set-cookie': this.getDeleteCookieHeaders()
				},
				body: {
					signout: true
				}
			};
		}

		const redirect = await this.getRedirectUrl(request.query.get('redirect') ?? undefined);

		return {
			status: 302,
			headers: {
				'set-cookie': this.getDeleteCookieHeaders(),
				Location: redirect
			}
		};
	}

	private async handleCallback(request: ServerRequest): Promise<EndpointOutput> {
		const { query, host } = request;
		const code = query.get('code');
		if (code == null) {
			throw new Error('Code not provided');
		}

		const redirectUrl = getStateValue(query, 'redirect');

		const tokens = await this.getTokens(code, this.getCallbackUri(host));
		const accessToken = tokens.access_token;
		const refreshToken = tokens.refresh_token;
		const expiresAt = getExpirationFromToken(tokens.access_token);

		const redirect = await this.getRedirectUrl(redirectUrl);

		return {
			status: 302,
			headers: {
				'set-cookie': this.getSetCookieHeaders(accessToken, refreshToken, expiresAt),
				Location: redirect
			}
		};
	}

	private getCallbackUri(host: string): string {
		return this.getUrl('/callback', host);
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

	private async handleRefresh(request: ServerRequest): Promise<EndpointOutput> {
		const { headers, query } = request;
		const { [refreshTokenCookieName]: oldRefreshToken } = cookie.parse(headers.cookie);
		try {
			const tokens = await this.getTokensForRefresh(oldRefreshToken);
			const newAccessToken = tokens.access_token;
			const newRefreshToken = tokens.refresh_token;
			const expiresAt = getExpirationFromToken(newAccessToken);

			if (request.method === 'GET') {
				const redirect = await this.getRedirectUrl(query.get('redirect') ?? undefined);
				return {
					status: 302,
					headers: {
						'set-cookie': this.getSetCookieHeaders(newAccessToken, newRefreshToken, expiresAt),
						Location: redirect
					}
				};
			} else {
				return {
					status: 200,
					headers: {
						'set-cookie': this.getSetCookieHeaders(newAccessToken, newRefreshToken, expiresAt)
					}
				};
			}
		} catch (error) {
			if (error instanceof RefreshTokenExpiredError) {
				if (request.method === 'GET') {
					const redirect = await this.getRedirectUrl(query.get('redirect') ?? undefined);
					return {
						status: 302,
						headers: {
							'set-cookie': this.getDeleteCookieHeaders(),
							Location: redirect
						}
					};
				} else {
					return {
						status: 403,
						headers: {
							'set-cookie': this.getDeleteCookieHeaders()
						}
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

	get: RequestHandler = async (request) => {
		return await this.handleEndpoint(request);
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
	const payloadBuffer = Buffer.from(payload, 'base64');
	const { exp } = JSON.parse(payloadBuffer.toString('utf-8'));

	if (exp == null) {
		throw new Error('exp claim must be specified');
	}

	return exp;
}

function getStateValue(query: URLSearchParams, name: string): string | undefined {
	const stateParam = query.get('state');
	if (stateParam) {
		const state = Buffer.from(stateParam, 'base64').toString();
		return state
			.split(',')
			.find((state) => state.startsWith(`${name}=`))
			?.replace(`${name}=`, '');
	}
}

type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
