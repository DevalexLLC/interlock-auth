import { AUTH_BASE_PATH } from "../core/constants.js";

export interface Endpoints {
  origin: string;
  authBaseURL: string;
  socketURL: string;
}

/** Relative URIs select the page origin; Interlock's routes are fixed. */
export function resolveEndpoints(uri?: string, location?: { origin: string }): Endpoints {
  const absolute = uri && /^[a-z][a-z\d+.-]*:/i.test(uri);
  const url = new URL(absolute ? uri : (location?.origin ?? "http://localhost"));
  if (!["http:", "https:"].includes(url.protocol))
    throw new TypeError("Interlock needs HTTP or HTTPS");
  const { origin } = url;
  return {
    origin,
    authBaseURL: `${origin}${AUTH_BASE_PATH}`,
    socketURL: `${origin.replace(/^http/, "ws")}/ws/irongate`,
  };
}
