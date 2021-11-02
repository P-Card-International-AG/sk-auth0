import type { RequestHandler } from '@sveltejs/kit';
import type { EndpointOutput } from '@sveltejs/kit/types/endpoint';
import type { ServerRequest } from '@sveltejs/kit/types/hooks';
import { join } from './path';
import type { Provider } from './providers';
import cookie from 'cookie';
import { RefreshTokenExpiredError } from './providers/errors';

interface AuthConfig {
	providers: Provider[];
	callbacks?: AuthCallbacks;
	host?: string;
	basePath: string;
	secure: boolean;
	domain?: string;
	sameSite: 'strict' | 'lax' | 'none' | boolean;
	maxAge: number;
}

interface AuthCallbacks {
	signIn?: () => boolean | Promise<boolean>;
	redirect?: (url: string) => string | Promise<string>;
}

const idTokenCookieName = 'svelteauth_id_token';
const refreshTokenCookieName = 'svelteauth_refresh_token';
const expiresAtCookieName = 'svelteauth_expires_at';
const providerCookieName = 'svelteauth_provider';

export class Auth {
	private readonly config: AuthConfig;

	constructor(config: Partial<AuthConfig>) {
		this.config = {
			maxAge: 60 * 60 * 24 * 30, // 30 days
			sameSite: 'strict',
			secure: true,
			basePath: '/api/auth',
			providers: [],
			...config
		};
	}

	getBaseUrl(host?: string): string {
		return this.config.host ?? `http://${host}`;
	}

	getPath(path: string): string {
		const pathname = join([this.config.basePath, path]);
		return pathname;
	}

	getUrl(path: string, host?: string): string {
		const pathname = this.getPath(path);
		return new URL(pathname, this.getBaseUrl(host)).href;
	}

	isSignedIn({ headers }: ServerRequest): boolean {
		const { [idTokenCookieName]: idToken } = cookie.parse(headers.cookie ?? '');

		return idToken != null;
	}

	getIdToken({ headers }: ServerRequest): string | null {
		const { [idTokenCookieName]: idToken } = cookie.parse(headers.cookie ?? '');
		return idToken;
	}

	async getRedirectUrl(redirectUrl?: string): Promise<string> {
		let redirect = redirectUrl ?? '/';
		if (this.config.callbacks?.redirect) {
			redirect = await this.config.callbacks.redirect(redirect);
		}
		return redirect;
	}

	async handleEndpoint(request: ServerRequest): Promise<EndpointOutput> {
		const { path } = request;

		if (path === this.getPath('signout')) {
			return await this.handleSignout(request);
		}

		const regex = new RegExp(
			join([this.config.basePath, `(?<method>signin|refresh|callback)/(?<provider>\\w+)`])
		);
		const match = path.match(regex);

		if (match && match.groups) {
			const providerString = match.groups.provider;
			const provider = this.config.providers?.find(
				(provider) => provider.getId() === providerString
			);
			if (provider) {
				if (match.groups.method === 'signin') {
					return await provider.signin(request, this);
				} else if (match.groups.method === 'refresh') {
					return await this.handleRefresh(request, provider);
				} else {
					return await this.handleProviderCallback(request, provider);
				}
			}
		}

		return {
			status: 404,
			body: 'Not found.'
		};
	}

	async handleSignout(request: ServerRequest): Promise<EndpointOutput> {
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

	async handleProviderCallback(
		request: ServerRequest,
		provider: Provider
	): Promise<EndpointOutput> {
		const { idToken, refreshToken, redirectUrl, expiresAt } = await provider.callback(
			request,
			this
		);
		const redirect = await this.getRedirectUrl(redirectUrl);

		return {
			status: 302,
			headers: {
				'set-cookie': this.getSetCookieHeaders(provider, idToken, refreshToken, expiresAt),
				Location: redirect
			}
		};
	}

	async handleRefresh(request: ServerRequest, provider: Provider): Promise<EndpointOutput> {
		const { headers, query } = request;
		const { [refreshTokenCookieName]: oldRefreshToken } = cookie.parse(headers.cookie);
		try {
			const {
				idToken: newIdToken,
				refreshToken: newRefreshToken,
				expiresAt
			} = await provider.refresh(oldRefreshToken, this);
			if (request.method === 'GET') {
				const redirect = await this.getRedirectUrl(query.get('redirect') ?? undefined);
				return {
					status: 302,
					headers: {
						'set-cookie': this.getSetCookieHeaders(
							provider,
							newIdToken,
							newRefreshToken,
							expiresAt
						),
						Location: redirect
					}
				};
			} else {
				return {
					status: 200,
					headers: {
						'set-cookie': this.getSetCookieHeaders(provider, newIdToken, newRefreshToken, expiresAt)
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

	get: RequestHandler = async (request) => {
		return await this.handleEndpoint(request);
	};

	post: RequestHandler = async (request) => {
		return await this.handleEndpoint(request);
	};

	private getSetCookieHeaders(
		provider: Provider,
		idToken: string,
		refreshToken: string | undefined,
		expiresAt: number
	): string[] {
		const cookies = [
			cookie.serialize(idTokenCookieName, idToken, this.getIdTokenCookieSettings()),
			cookie.serialize(
				expiresAtCookieName,
				expiresAt.toString(),
				this.getExpiresAtCookieSettings()
			),
			cookie.serialize(providerCookieName, provider.getId(), this.getProviderCookieSettings())
		];

		if (refreshToken != null) {
			cookies.push(
				cookie.serialize(refreshTokenCookieName, refreshToken, {
					...this.getRefreshTokenCookieSettings(),
					path: `${this.config.basePath}${provider.getRefreshPath()}`
				})
			);
		}

		return cookies;
	}

	private getDeleteCookieHeaders() {
		return [
			cookie.serialize(idTokenCookieName, '', {
				...this.getIdTokenCookieSettings(),
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
			}),
			cookie.serialize(providerCookieName, '', {
				...this.getProviderCookieSettings(),
				maxAge: undefined,
				expires: new Date(1970, 1, 1, 0, 0, 0, 0)
			})
		];
	}

	private getIdTokenCookieSettings(): cookie.CookieSerializeOptions {
		return {
			httpOnly: true,
			path: '/',
			sameSite: this.config.sameSite,
			secure: this.config.secure,
			domain: this.config.domain,
			maxAge: this.config.maxAge
		};
	}

	private getRefreshTokenCookieSettings(): cookie.CookieSerializeOptions {
		return {
			httpOnly: true,
			sameSite: this.config.sameSite,
			secure: this.config.secure,
			domain: this.config.domain,
			maxAge: this.config.maxAge
		};
	}

	private getExpiresAtCookieSettings(): cookie.CookieSerializeOptions {
		return {
			path: '/',
			sameSite: this.config.sameSite,
			secure: this.config.secure,
			domain: this.config.domain,
			maxAge: this.config.maxAge
		};
	}

	private getProviderCookieSettings(): cookie.CookieSerializeOptions {
		return {
			path: '/',
			sameSite: this.config.sameSite,
			secure: this.config.secure,
			domain: this.config.domain,
			maxAge: this.config.maxAge
		};
	}
}