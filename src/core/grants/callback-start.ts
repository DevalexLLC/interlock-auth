import { performance } from "node:perf_hooks";

import type { BetterAuthOptions } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";

/** The core endpoint every OAuth callback is served by, as `ctx.path` reports it. */
export const CALLBACK_ENDPOINT = "/callback/:id";

type BeforeHook = NonNullable<NonNullable<BetterAuthOptions["hooks"]>["before"]>;
type AfterHook = NonNullable<NonNullable<BetterAuthOptions["hooks"]>["after"]>;

/**
 * When each callback request started, on the monotonic clock, keyed by the
 * request's auth context: Better Auth builds one per request, and the before
 * hook and the database hooks of that request see the same object.
 */
const callbackStarts = new WeakMap<object, number>();

/**
 * The `performance.now()` at which the callback that owns this auth context
 * started, or undefined outside a callback (or in a build without the hook).
 */
export const callbackStartOf = (authContext: object | null | undefined) =>
  authContext ? callbackStarts.get(authContext) : undefined;

/**
 * Records the start of every `/callback/:id` request, before the code
 * exchange leaves the process, as the anchor of the login's deadlines: every
 * later point (core stamps its expiry when the exchange response is parsed,
 * `accountSubject` runs after the userinfo fetch) would credit time already
 * spent to the session. Anchored here, a deadline can only err short.
 *
 * It answers nothing and blocks nothing; on every other path it returns at once.
 */
export const recordCallbackStart = () =>
  createAuthMiddleware(async (ctx) => {
    if (ctx.path === CALLBACK_ENDPOINT) {
      callbackStarts.set(ctx.context, performance.now());
    }
    return Promise.resolve();
  });

/**
 * Better Auth takes one user `before` hook; this runs several in order, so
 * each hook (the exposure allow-list first) joins the list rather than
 * replacing it. A hook that throws stops the list and answers with its error.
 * Each runs as Better Auth runs a hook, with `returnHeaders`, so the headers
 * it set are carried over; the first to return a value answers for all.
 */
export const composeBeforeHooks = (hooks: BeforeHook[]): BeforeHook =>
  createAuthMiddleware(async (ctx) => {
    for (const hook of hooks) {
      const { headers, response } = (await hook({ ...ctx, returnHeaders: true })) as {
        headers?: Headers;
        response?: unknown;
      };
      for (const cookie of headers?.getSetCookie() ?? []) {
        ctx.responseHeaders.append("set-cookie", cookie);
      }
      headers?.forEach((value, name) => {
        if (name !== "set-cookie") {
          ctx.setHeader(name, value);
        }
      });
      if (response !== undefined) {
        return response;
      }
    }
    return undefined;
  });

/**
 * The `after` counterpart of `composeBeforeHooks`: Better Auth takes one user
 * `after` hook, so this runs several in order, carrying each one's headers
 * over. A hook that returns a value replaces the result the next one sees,
 * as Better Auth does between hooks.
 */
export const composeAfterHooks = (hooks: AfterHook[]): AfterHook =>
  createAuthMiddleware(async (ctx) => {
    let replaced: unknown;
    for (const hook of hooks) {
      const { headers, response } = (await hook({ ...ctx, returnHeaders: true })) as {
        headers?: Headers;
        response?: unknown;
      };
      for (const cookie of headers?.getSetCookie() ?? []) {
        ctx.responseHeaders.append("set-cookie", cookie);
      }
      headers?.forEach((value, name) => {
        if (name !== "set-cookie") {
          ctx.setHeader(name, value);
        }
      });
      if (response !== undefined) {
        ctx.context.returned = response;
        replaced = response;
      }
    }
    return replaced;
  });
