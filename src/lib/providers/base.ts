import type { EndpointOutput } from '@sveltejs/kit';
import type { ServerRequest } from '@sveltejs/kit/types/hooks';
import type { Auth } from '../auth';
import type { CallbackResult, RefreshResult } from '../types';

export interface ProviderConfig {
	id: string;
}

export abstract class Provider<T extends ProviderConfig = ProviderConfig> {
	constructor(protected readonly config: T) {}

	getId(): string {
		return this.config.id;
	}

	getUri(svelteKitAuth: Auth, path: string, host?: string): string {
		return svelteKitAuth.getUrl(path, host);
	}

	getCallbackUri(svelteKitAuth: Auth, host?: string): string {
		return this.getUri(svelteKitAuth, `${'/callback/'}${this.config.id}`, host);
	}

	getRefreshPath(): string {
		return `/refresh/${this.config.id}`;
	}

	abstract signin<Locals extends Record<string, unknown> = Record<string, unknown>, Body = unknown>(
		request: ServerRequest<Locals, Body>,
		svelteKitAuth: Auth
	): EndpointOutput | Promise<EndpointOutput>;

	abstract callback<
		Locals extends Record<string, unknown> = Record<string, unknown>,
		Body = unknown
	>(
		request: ServerRequest<Locals, Body>,
		svelteKitAuth: Auth
	): CallbackResult | Promise<CallbackResult>;

	abstract refresh(
		refreshToken: string,
		svelteKitAuth: Auth
	): RefreshResult | Promise<RefreshResult>;
}
