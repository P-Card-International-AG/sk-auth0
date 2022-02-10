# SvelteKit Auth0

## Setup auth0

1. Create a regular web application in auth0.
2. Enable refresh tokens by enabling the `Rotation` toggle in the `Refresh Token Rotation` section.
3. Create an API in auth0
4. Goto settings
5. Enable the `Allow Offline Access` toggle in the `Access Settings` section.

You can copy the access keys from the settings tab in the regular web application.
The needed info is in Domain, Client ID, Client Secret.
The Audience needs to be the identifier (Api audience) of the api.

Add the allowed callback url "http://localhost:3000/\*" in the "Application URIs" section of the "Settings" tab in the Regular web application

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

Next, edit the `src/app.d.ts` file:

```TS
/* eslint-disable @typescript-eslint/no-empty-interface */
/// <reference types="@sveltejs/kit" />

declare namespace App {
	interface Locals {
		accessToken: string | null;
	}

	interface Platform {}

	interface Session {
		isSignedIn: boolean;
	}

	interface Stuff {}
}
```

Here we define the type for the svelte session.

Then create the following `src/hooks.ts` file:

```TS
import { sequence } from '@sveltejs/kit/hooks';
import { appAuth } from '$lib/auth';
import type { GetSession } from '@sveltejs/kit';

export const handle = sequence(appAuth.handle);

export const getSession: GetSession = (request) => {
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

You can sign in and logout like this:

```SVELTE
<script lang="ts">
	import { session } from '$app/stores';
	import { signIn, signOut } from '@nicolas.seiler/sk-auth/client';
</script>

{#if $session.isSignedIn}
	<p>Hello user</p>
	<button type="button" on:click={() => signOut()}>Logout</button>
{:else}
	<p>Who are you?</p>
	<button type="button" on:click={() => signIn()}>Sign in</button>
{/if}
```
