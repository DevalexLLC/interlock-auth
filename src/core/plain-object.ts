/**
 * An object literal or a null-prototype object, from any realm: its prototype
 * is null or a root object. A parsed request body can come from another
 * realm's `JSON.parse` (the fetch implementation's, under Jest), so a
 * comparison with this realm's `Object.prototype` would miss it. A `Date`,
 * an `APIError` or a `Response` has a longer chain and is not one.
 */
export const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: object | null = Object.getPrototypeOf(value) as object | null;
  return proto === null || Object.getPrototypeOf(proto) === null;
};
