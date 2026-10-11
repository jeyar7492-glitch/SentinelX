/**
 * SentinelX Utility Helpers
 */

export function truncateUrl(url: string, maxLength = 50): string {
  if (url.length <= maxLength) {
    return url;
  }
  return url.substring(0, maxLength - 3) + "...";
}

export function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function isValidWebUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}
