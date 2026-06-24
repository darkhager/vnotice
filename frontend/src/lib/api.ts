const DEFAULT_PORT = "8080";

/**
 * Returns the backend base URL derived from the current browser host.
 * Works on any IP (DHCP/LAN) because it follows window.location.hostname.
 * Override at build-time via NEXT_PUBLIC_API_URL env var.
 */
export function getApiBase(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL.replace(/\/$/, "");
  }
  if (typeof window !== "undefined") {
    return `http://${window.location.hostname}:${DEFAULT_PORT}`;
  }
  return `http://localhost:${DEFAULT_PORT}`;
}
