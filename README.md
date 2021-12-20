# SvelteKit Auth0

## Setup auth0

1. Create a regular web application in auth0.
2. Enable refresh tokens by enabling the `Rotation` toggle in the `Refresh Token Rotation` section.
3. Create an API in auth0 and enable the `Allow Offline Access` toggle in the `Access Settings` section.

## Usage

Create the following `src/lib/auth.ts` file:

```TS
import { SvelteKitAuth } from '@nicolas.seiler/sk-auth';

export const appAuth = new SvelteKitAuth({
	auth0Domain: import.meta.env.VITE_AUTH0_DOMAIN,
	clientId: import.meta.env.VITE_AUTH0_CLIENT_ID,
	clientSecret: import.meta.env.VITE_AUTH0_CLIENT_SECRET,
	audience: import.meta.env.VITE_AUTH0_AUDIENCE
});
```

Add the corresponding values to your `.env` file.

Be careful to **NEVER** import this file in any of your components or pages. Doing so will leak the auth0 client secret to the frontend.

Next, create the following `src/lib/session.ts` file:

```TS
export interface Session {
	isSignedIn: boolean;
}
```

Here we define the type for the svelte session.

Then create the following `src/hooks.ts` file:

```TS
import { sequence } from '@sveltejs/kit/hooks';
import { appAuth } from '$lib/auth';
import type { GetSession } from '@sveltejs/kit';
import type { Session } from '$lib/session';

export const handle = sequence(appAuth.handle);

export const getSession: GetSession<Record<string, unknown>, unknown, Session> = (request) => {
	return {
		isSignedIn: appAuth.isSignedIn(request)
	};
};
```

This sets the isSignedIn flag on the svelte session object.

Finally, create the following `src/routes/api/auth/[...auth].ts` file:
```TS
import { appAuth } from '$lib/auth';

export const { get, post } = appAuth;
```
This adds the endpoints needed by the library.

You can now call `signIn` or `signOut` imported from `'$lib/sk-auth/client'` in your application.