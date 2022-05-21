# SvelteKit Auth0

A Auth0 integration for SvelteKit.
This integration uses http only cookies so that the js has no access to the jwt.
You have to pass all requests to external services through a proxy so that the server can inspect the cookie and attach it to the request.

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
import { SvelteKitAuth } from 'sk-auth0';

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

You can now call `signIn` or `signOut` imported from `'sk-auth0/client'` in your application.

You can sign in and logout like this:

```SVELTE
<script lang="ts">
	import { session } from '$app/stores';
	import { signIn, signOut } from 'sk-auth0/client';
</script>

{#if $session.isSignedIn}
	<p>Hello user</p>
	<button type="button" on:click={() => signOut()}>Logout</button>
{:else}
	<p>Who are you?</p>
	<button type="button" on:click={() => signIn()}>Sign in</button>
{/if}
```

### Refreshing the access token

When a user opens your website while his access token is expired, `sk-auth0` will automatically refresh it.

To ensure that the token is also refreshed when the token expires while the user still has the page open, you have to call the `ensureTokenRefreshed` function before every API call your app does. The easiest way to do this is to wrap the `fetch` function with `wrapFetch` like so:

```TS
import { wrapFetch } from 'sk-auth0/client';
import { browser } from "$app/env";

// Pass the fetch that you want to wrap. In the load function this is the fetch you get from svelte-kit.
const wrappedFetch = wrapFetch(fetch, browser);

// You can wrap the fetch in your __layout.svelte and pass it to your GraphQL Client or child components via svelte-kit stuff.
wrappedFetch("https://example.com").then(response => console.log(response));
```
