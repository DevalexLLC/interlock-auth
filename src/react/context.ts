import { createContext, useContext } from "react";

import type { CatalogClient } from "../client/catalog.js";
import type { InterlockFetch } from "../client/fetch.js";
import type { SessionController } from "../client/session-controller.js";
import type { SocketConnector } from "../client/socket-connector.js";

export interface InterlockContextValue {
  controller: SessionController;
  fetch: InterlockFetch;
  catalog: CatalogClient;
  socket: SocketConnector;
}
export const InterlockContext = createContext<InterlockContextValue | null>(null);
export function useInterlockContext() {
  const context = useContext(InterlockContext);
  if (!context) throw new Error("Interlock hooks require an InterlockProvider");
  return context;
}
