interface SignInConfig {
	redirectUrl?: string;
}

export function signIn(config?: SignInConfig): void {
	window.location.href = signInUrl(config);
}

export function signInUrl(config?: SignInConfig): string {
	let redirectUrl: string | undefined;
	if (config?.redirectUrl) {
		redirectUrl = config.redirectUrl;
	} else {
		redirectUrl = window.location.pathname + window.location.search + window.location.hash;
	}

	const queryData = {
		redirect: redirectUrl
	};
	const query = new URLSearchParams(queryData);

	return `/api/auth/signin?${query}`;
}
