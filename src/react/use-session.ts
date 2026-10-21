import { useSyncExternalStore } from "react";

import { useInterlockContext } from "./context.js";

export function useInterlockSession() {
  const { controller } = useInterlockContext();
  const state = useSyncExternalStore(
    controller.subscribe,
    controller.getState,
    controller.getState,
  );
  const user =
    state.phase.kind === "signed_in" || state.phase.kind === "signing_out"
      ? (state.phase.session?.user ?? null)
      : null;
  return {
    ...state,
    user,
    isSignedIn: state.phase.kind === "signed_in",
    signIn: controller.signIn,
    signOut: controller.signOut,
    retry: controller.retry,
  };
}
