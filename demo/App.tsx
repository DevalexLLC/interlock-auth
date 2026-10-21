import { useEffect, useState } from "react";

import {
  InterlockProvider,
  useCatalogClient,
  useInterlockSession,
  useNotificationSocket,
  useSocketEvent,
  type Application,
  type KeycloakGroup,
  type UserRequest,
} from "../src/react/index.js";

type CatalogRow = { application: Application; groups: KeycloakGroup[] };
function Dashboard() {
  const session = useInterlockSession();
  const catalog = useCatalogClient();
  const socket = useNotificationSocket();
  const [rows, setRows] = useState<CatalogRow[]>([]);
  const [requests, setRequests] = useState<UserRequest[]>([]);
  const [groups, setGroups] = useState<KeycloakGroup[]>([]);
  const [message, setMessage] = useState("");
  const [lastEvent, setLastEvent] = useState<unknown>(null);
  const [revision, setRevision] = useState(0);
  const username = session.user?.username;
  const id = session.phase.kind === "signed_in" ? session.phase.session.session.id : null;
  useSocketEvent("notifications", setLastEvent);
  useEffect(() => {
    if (!id) return undefined;
    let active = true;
    const load = async () => {
      const [applications, ownGroups, ownRequests] = await Promise.all([
        catalog.listApplications(),
        catalog.myGroups(),
        username ? catalog.listMyRequests(username) : Promise.resolve([]),
      ]);
      const nextRows = await Promise.all(
        applications.map(async (application) => ({
          application,
          groups: await catalog.groupsGranting(application.id),
        })),
      );
      if (active) {
        setRows(nextRows);
        setGroups(ownGroups);
        setRequests(ownRequests);
      }
    };
    void load().catch((error: unknown) => {
      if (active) setMessage(error instanceof Error ? error.message : "Request failed");
    });
    return () => {
      active = false;
    };
  }, [id, username, catalog, revision]);
  const act = (action: () => Promise<unknown>) => {
    void action()
      .then(() => setRevision((value) => value + 1))
      .catch((error: unknown) =>
        setMessage(error instanceof Error ? error.message : "Request failed"),
      );
  };
  const signOut = session.phase.kind === "signed_out" ? session.phase : null;
  return (
    <main>
      <header>
        <p className="eyebrow">COMPOSE DEVELOPMENT ONLY</p>
        <h1>Interlock client demo</h1>
        <p>
          Session: <strong>{session.phase.kind}</strong>
        </p>
      </header>
      {session.dependency && (
        <aside role="alert">
          Dependency unavailable: {session.dependency.source} / {session.dependency.reason}.{" "}
          <button
            type="button"
            onClick={() => {
              void session.retry();
            }}
          >
            Retry session
          </button>
        </aside>
      )}
      <nav>
        <button
          type="button"
          onClick={() => {
            void session.signIn();
          }}
        >
          Sign in
        </button>
        <button
          type="button"
          disabled={session.phase.kind === "signing_out"}
          onClick={() => {
            void session.signOut();
          }}
        >
          Sign out everywhere
        </button>
        <button
          type="button"
          onClick={() => {
            void session.retry();
          }}
        >
          Revalidate session
        </button>
      </nav>
      {signOut && (
        <section>
          <h2>Signed out</h2>
          <p>
            {signOut.keycloakLogout === "unconfirmed"
              ? "Signed out of this application, SSO may still be active"
              : signOut.keycloakLogout === "ended"
                ? "Your Keycloak session has ended."
                : "Sign in to continue."}
          </p>
          {signOut.signOutIncomplete && (
            <p role="alert">
              Sign-out cleanup is incomplete. This request will not be retried automatically.
            </p>
          )}
        </section>
      )}
      {session.isSignedIn && (
        <>
          <section>
            <h2>{session.user?.name}</h2>
            <p>Username: {username ?? "Not yet provided — sign in again after migrating"}</p>
            <p>
              Email:{" "}
              {session.user?.email.endsWith("@keycloak.invalid")
                ? "Not provided (placeholder)"
                : session.user?.email}
            </p>
            <p>My groups: {groups.map((group) => group.path).join(", ") || "None"}</p>
          </section>
          <section>
            <h2>Applications</h2>
            {rows.map(({ application, groups: granting }) => (
              <article key={application.id}>
                <h3>
                  <a href={application.url}>{application.name}</a>
                </h3>
                <p>{application.description}</p>
                <p>{application.requestable ? "Requestable" : "Not requestable"}</p>
                {granting.map((group) => (
                  <p key={group.id}>
                    {group.path}{" "}
                    <button
                      type="button"
                      disabled={!application.requestable || !username}
                      onClick={() =>
                        act(async () => {
                          if (!username) return;
                          const result = await catalog.createMemberRequest({
                            group: group.path,
                            user: username,
                            clientId: application.id,
                          });
                          setMessage(
                            result.kind === "already_requested"
                              ? "Already requested"
                              : "Request created",
                          );
                        })
                      }
                    >
                      Request access
                    </button>
                  </p>
                ))}
              </article>
            ))}
          </section>
          <section>
            <h2>My requests</h2>
            {requests.map((request) => (
              <p key={request.id}>
                {request.group} · {request.clientId}{" "}
                <button
                  type="button"
                  onClick={() => act(async () => catalog.cancelRequest(request.id))}
                >
                  Cancel
                </button>
              </p>
            ))}
          </section>
        </>
      )}
      {message && <p role="status">{message}</p>}
      <section>
        <h2>Notification socket</h2>
        <p>
          {socket.phase} · attempt {socket.attempt}
        </p>
        <p>Last failure: {socket.failure?.reason ?? "None"}</p>
        <button type="button" onClick={socket.reconnectNow}>
          Reconnect now
        </button>
        <pre>{JSON.stringify(lastEvent, null, 2)}</pre>
      </section>
      <footer>
        This page validates the local Compose stack. It provides no cluster or enclave evidence.
      </footer>
    </main>
  );
}
export function App() {
  return (
    <InterlockProvider
      uri={import.meta.env.VITE_INTERLOCK_URI || "https://interlock.dev.home.arpa"}
    >
      <Dashboard />
    </InterlockProvider>
  );
}
