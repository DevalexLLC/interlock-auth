import { createAuthClient } from "better-auth/react";

import { dependencyFailure } from "../client/dependency-failure.js";
import type { Endpoints } from "../client/endpoints.js";
import { DependencyFailureError, UpstreamError } from "../client/errors.js";
import type { SignInOptions } from "../client/session-controller.js";
import type { SignOutResponse } from "../client/types.js";

export function createInterlockAuthClient(
  endpoints: Endpoints,
  {
    fetch: fetchImpl = globalThis.fetch,
    refetchIntervalSeconds = 60,
    navigate = (url: string) => {
      window.location.assign(url);
    },
  }: {
    fetch?: typeof fetch;
    refetchIntervalSeconds?: number;
    navigate?: (url: string) => void;
  } = {},
) {
  const client = createAuthClient({
    baseURL: endpoints.authBaseURL,
    disableDefaultFetchPlugins: true,
    fetchOptions: { customFetchImpl: fetchImpl, credentials: "include", retry: 0 },
    sessionOptions: { refetchInterval: refetchIntervalSeconds, refetchOnWindowFocus: true },
  });
  const sessionAtom = client.$store.atoms.session;
  if (!sessionAtom) throw new Error("Better Auth has no session atom");
  return {
    useSession: client.useSession,
    refetchSession: () => sessionAtom.get().refetch(),
    signIn: async ({ callbackURL }: SignInOptions) => {
      const { data, error } = await client.signIn.social({
        provider: "keycloak",
        callbackURL,
        disableRedirect: true,
      });
      if (error) throw new UpstreamError(error.status, error);
      if (!data?.url) throw new Error("Interlock did not return a login URL");
      navigate(data.url);
    },
    signOut: async (): Promise<SignOutResponse> => {
      const { data, error } = await client.signOut();
      const body = (error ?? data) as { code?: string; keycloakLogout?: string } | null;
      const incomplete = error?.status === 503 && body?.code === "sign_out_incomplete";
      if (error && !incomplete)
        throw new DependencyFailureError(
          dependencyFailure("session", "sign_out_failed", { status: error.status }),
        );
      const outcome = body?.keycloakLogout;
      if (outcome !== "ended" && outcome !== "unconfirmed" && outcome !== "no_session")
        throw new Error("Interlock returned an invalid sign-out outcome");
      return { keycloakLogout: outcome, incomplete };
    },
  };
}
