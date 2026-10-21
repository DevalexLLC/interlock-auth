import { useInterlockContext } from "./context.js";
export const useInterlockFetch = () => useInterlockContext().fetch;
export const useCatalogClient = () => useInterlockContext().catalog;
