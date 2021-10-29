import type { EndpointOutput } from "@sveltejs/kit/types/endpoint";
import type { ServerRequest } from "@sveltejs/kit/types/hooks";
import type { Auth } from "../auth";
import type { CallbackResult, RefreshResult } from "../types";
import { Provider, ProviderConfig } from "./base";

export interface OAuth2Tokens {
  id_token: string;
  refresh_token: string;
  token_type: string;
}

export abstract class OAuth2BaseProvider<
  TokensType extends OAuth2Tokens,
  T extends ProviderConfig,
> extends Provider<T> {
  abstract getAuthorizationUrl(
    request: ServerRequest,
    auth: Auth,
    state: string,
    nonce: string,
  ): string | Promise<string>;
  protected abstract getTokens(code: string, redirectUri: string): TokensType | Promise<TokensType>;
  protected abstract getTokensForRefresh(refreshToken: string): TokensType | Promise<TokensType>;

  async signin(request: ServerRequest, auth: Auth): Promise<EndpointOutput> {
    const { method, host, query } = request;
    const state = [`redirect=${query.get("redirect") ?? this.getUri(auth, "/", host)}`].join(",");
    const base64State = Buffer.from(state).toString("base64");
    const nonce = Math.round(Math.random() * 1000).toString(); // TODO: Generate random based on user values
    const url = await this.getAuthorizationUrl(request, auth, base64State, nonce);

    if (method === "POST") {
      return {
        body: {
          redirect: url,
        },
      };
    }

    return {
      status: 302,
      headers: {
        Location: url,
      },
    };
  }

  getStateValue(query: URLSearchParams, name: string) {
    if (query.get("state")) {
      const state = Buffer.from(query.get("state")!, "base64").toString();
      return state
        .split(",")
        .find((state) => state.startsWith(`${name}=`))
        ?.replace(`${name}=`, "");
    }
  }

  public override async callback(
    { query, host }: ServerRequest,
    auth: Auth,
  ): Promise<CallbackResult> {
    const code = query.get("code");
    if (code == null) {
      throw new Error("Code not provided");
    }

    const redirect = this.getStateValue(query, "redirect");

    const tokens = await this.getTokens(code, this.getCallbackUri(auth, host));
    const exp = getExpirationFromIdToken(tokens.id_token);

    return {
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      redirectUrl: redirect,
      expiresAt: exp,
    };
  }

  public override async refresh(refreshToken: string): Promise<RefreshResult> {
    const tokens = await this.getTokensForRefresh(refreshToken);
    const exp = getExpirationFromIdToken(tokens.id_token);

    return {
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      expiresAt: exp,
    };
  }
}

function getExpirationFromIdToken(idToken: string): number {
  const [_, payload] = idToken.split(".");
  const payloadBuffer = Buffer.from(payload, "base64");
  const { exp } = JSON.parse(payloadBuffer.toString("utf-8"));

  if (exp == null) {
    throw new Error("exp claim must be specified");
  }

  return exp;
}
