import { UpstreamError } from "./errors.js";
import type { InterlockFetch, InterlockRequestInit } from "./fetch.js";

export interface Application {
  id: string;
  name: string;
  url: string;
  description: string;
  requestable: boolean;
  legacyClientIds?: string[];
}
export interface KeycloakGroup {
  id: string;
  name: string;
  path: string;
  attributes?: Record<string, string[]>;
}
export interface UserRequest {
  id: string;
  group: string;
  user: string;
  clientId: string;
  type: string;
  action: string;
  [key: string]: unknown;
}
export interface Notification {
  _id?: string;
  id?: string;
  [key: string]: unknown;
}
const requestId = (body: Record<string, unknown>) =>
  ({
    ...body,
    id: typeof body._id === "string" ? body._id : typeof body.id === "string" ? body.id : "",
  }) as UserRequest;
export function createCatalogClient(fetch: InterlockFetch) {
  const request = async (path: string, init?: InterlockRequestInit) => {
    const response = await fetch(`/api/irongate${path}`, init);
    let body: unknown = null;
    if (response.status !== 204) {
      try {
        body = await response.json();
      } catch {
        /* Preserve status for errors without JSON. */
      }
    }
    if (!response.ok) throw new UpstreamError(response.status, body);
    return body;
  };
  return {
    listApplications: async () => (await request("/applications")) as Application[],
    groupsGranting: async (appId: string) =>
      (await request("/keycloak/groups/all", {
        query: { "attributes.apps": appId },
      })) as KeycloakGroup[],
    myGroups: async () => (await request("/keycloak/users/me/groups")) as KeycloakGroup[],
    listMyRequests: async (user: string) =>
      ((await request("/user-requests", { query: { user } })) as Record<string, unknown>[]).map(
        requestId,
      ),
    createMemberRequest: async (input: {
      group: string;
      user: string;
      clientId: string;
    }): Promise<{ kind: "created"; request: UserRequest } | { kind: "already_requested" }> => {
      try {
        return {
          kind: "created",
          request: requestId(
            (await request("/user-requests", {
              method: "POST",
              json: { ...input, type: "keycloak-member", action: "add" },
            })) as Record<string, unknown>,
          ),
        };
      } catch (error) {
        if (error instanceof UpstreamError && error.status === 409)
          return { kind: "already_requested" };
        throw error;
      }
    },
    cancelRequest: async (id: string) => {
      await request(`/user-requests/${encodeURIComponent(id)}`, { method: "DELETE" });
    },
    listNotifications: async (clientId: string) =>
      (await request("/notifications", { query: { clientId } })) as Notification[],
    notificationCount: async () => (await request("/notifications/count")) as { count: number },
  };
}
export type CatalogClient = ReturnType<typeof createCatalogClient>;
