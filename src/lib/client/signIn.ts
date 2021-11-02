interface SignInConfig {
	redirectUrl?: string;
}

export function signIn(provider: string, config?: SignInConfig) {
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
	const path = `/api/auth/signin/${provider}?${query}`;

	window.location.href = path;
}
