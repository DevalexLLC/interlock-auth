import { useEffect, useRef, useSyncExternalStore } from "react";

import { useInterlockContext } from "./context.js";

export function useNotificationSocket() {
  const { socket } = useInterlockContext();
  const state = useSyncExternalStore(socket.subscribe, socket.getState, socket.getState);
  return {
    ...state,
    send: socket.send,
    subscribe: socket.subscribeMessages,
    reconnectNow: socket.reconnectNow,
  };
}
// The consumer supplies the event payload type; the wire envelope is checked by the connector.
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters
export function useSocketEvent<T = unknown>(event: string, handler: (data: T) => void) {
  const { socket } = useInterlockContext();
  const current = useRef(handler);
  useEffect(() => {
    current.current = handler;
  }, [handler]);
  useEffect(
    () =>
      socket.subscribeMessages((message) => {
        if (message.event === event) current.current(message.data as T);
      }),
    [socket, event],
  );
}
