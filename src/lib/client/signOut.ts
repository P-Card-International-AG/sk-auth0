interface SignOutConfig {
	redirectUrl?: string;
}

export function signOut(config?: SignOutConfig) {
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
	const path = `/api/auth/signout?${query}`;

	window.location.href = path;
}
