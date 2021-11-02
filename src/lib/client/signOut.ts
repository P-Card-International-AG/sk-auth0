interface SignOutConfig {
	redirectUrl?: string;
}

export function signOut(config?: SignOutConfig): void {
	window.location.href = signOutUrl(config);
}

export function signOutUrl(config?: SignOutConfig): string {
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

	return `/api/auth/signout?${query}`;
}
