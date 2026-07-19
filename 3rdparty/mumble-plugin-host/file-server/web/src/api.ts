// Pure frontend auth client. Mirrors the server contract exactly: read the file
// id + signed params from the current URL, exchange the password for a
// single-use ticket via POST /files/{id}/auth, then hand back the ticketed
// download URL to redirect to. No app state, no framework - easy to unit test.

/** base64url WITHOUT padding (matches the server's `URL_SAFE_NO_PAD`). */
export function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A user-presentable failure to exchange the password for a ticket. */
export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

/**
 * Exchange `password` for a single-use ticket and return the ticketed download
 * URL to navigate to. Throws {@link AuthError} with a friendly message on any
 * failure.
 */
export async function authenticate(password: string): Promise<string> {
  const basePath = window.location.pathname; // /files/{id}
  const params = new URLSearchParams(window.location.search);

  let response: Response;
  try {
    response = await fetch(`${basePath}/auth`, {
      method: "POST",
      headers: { Authorization: `Bearer ${base64UrlEncode(password)}` },
    });
  } catch {
    throw new AuthError("Network error. Please try again.");
  }

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new AuthError("Incorrect password. Please try again.");
    }
    if (response.status === 429) {
      throw new AuthError("Too many attempts. Please wait and try again.");
    }
    throw new AuthError("Something went wrong. Please try again.");
  }

  const data = (await response.json().catch(() => null)) as {
    ticket?: unknown;
  } | null;
  const ticket = data && data.ticket ? String(data.ticket) : "";
  if (!ticket) {
    throw new AuthError("Something went wrong. Please try again.");
  }

  const ex = params.get("ex") ?? "";
  const is = params.get("is") ?? "";
  const hm = params.get("hm") ?? "";
  return (
    `${basePath}?ex=${encodeURIComponent(ex)}` +
    `&is=${encodeURIComponent(is)}` +
    `&hm=${encodeURIComponent(hm)}` +
    `&ticket=${encodeURIComponent(ticket)}`
  );
}
