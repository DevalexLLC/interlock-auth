import { describe, expect, it, vi } from "vitest";

import { createCatalogClient } from "./catalog.js";
import { SessionEndedError, UpstreamError } from "./errors.js";
import type { InterlockFetch } from "./fetch.js";

describe("catalog routes", () => {
  it.each([
    ["listApplications", [], "/applications", undefined, []],
    [
      "groupsGranting",
      ["illumina"],
      "/keycloak/groups/all",
      { query: { "attributes.apps": "illumina" } },
      [],
    ],
    ["myGroups", [], "/keycloak/users/me/groups", undefined, []],
    ["listMyRequests", ["ann"], "/user-requests", { query: { user: "ann" } }, []],
    ["listNotifications", ["irongate"], "/notifications", { query: { clientId: "irongate" } }, []],
    ["notificationCount", [], "/notifications/count", undefined, { count: 0 }],
    ["cancelRequest", ["a/b"], "/user-requests/a%2Fb", { method: "DELETE" }, {}],
  ] as const)("%s uses its BFF route", async (method, args, path, init, body) => {
    const fetch = vi.fn<InterlockFetch>().mockResolvedValue(Response.json(body));
    const client = createCatalogClient(fetch);
    const invoke = client[method] as (...args: string[]) => Promise<unknown>;
    await invoke(...args);
    expect(fetch).toHaveBeenCalledWith(`/api/irongate${path}`, init);
  });
  it.each(["_id", "id"])("member request accepts %s and sets type and action", async (idField) => {
    const fetch = vi.fn<InterlockFetch>().mockResolvedValue(Response.json({ [idField]: "r1" }));
    const input = { group: "/Apps/Illumina", user: "ann", clientId: "illumina" };
    expect(await createCatalogClient(fetch).createMemberRequest(input)).toMatchObject({
      kind: "created",
      request: { id: "r1" },
    });
    expect(fetch).toHaveBeenCalledWith("/api/irongate/user-requests", {
      method: "POST",
      json: { ...input, type: "keycloak-member", action: "add" },
    });
  });
  it("409 is already_requested; upstream 500 is an UpstreamError", async () => {
    const fetch = vi
      .fn<InterlockFetch>()
      .mockResolvedValueOnce(Response.json({}, { status: 409 }))
      .mockResolvedValueOnce(Response.json({}, { status: 500 }));
    const client = createCatalogClient(fetch);
    expect(await client.createMemberRequest({ group: "g", user: "u", clientId: "c" })).toEqual({
      kind: "already_requested",
    });
    await expect(client.listApplications()).rejects.toBeInstanceOf(UpstreamError);
  });
  it("SessionEndedError passes through unchanged", async () => {
    const error = new SessionEndedError(2);
    await expect(
      createCatalogClient(vi.fn().mockRejectedValue(error)).listApplications(),
    ).rejects.toBe(error);
  });
});
