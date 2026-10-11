import test from "node:test";
import assert from "node:assert/strict";
import { escapeHtml, isValidWebUrl, truncateUrl } from "../dist/utils.js";

test("truncateUrl keeps short URLs intact", () => {
  const short = "https://example.com";
  assert.equal(truncateUrl(short, 50), short);
});

test("truncateUrl truncates long URLs with ellipsis", () => {
  const longUrl = "https://example.com/very/long/path/with/many/segments/and/arguments?query=123456789";
  const truncated = truncateUrl(longUrl, 30);
  assert.equal(truncated.length, 30);
  assert.ok(truncated.endsWith("..."));
});

test("escapeHtml sanitizes HTML entities to prevent XSS", () => {
  const dirty = '<script>alert("xss")</script>&foo=\'bar\'';
  const clean = escapeHtml(dirty);
  assert.equal(clean, '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;&amp;foo=&#039;bar&#039;');
});

test("isValidWebUrl validates http and https while rejecting others", () => {
  assert.equal(isValidWebUrl("https://example.com"), true);
  assert.equal(isValidWebUrl("http://192.168.1.1"), true);
  assert.equal(isValidWebUrl("chrome://extensions"), false);
  assert.equal(isValidWebUrl("javascript:alert(1)"), false);
  assert.equal(isValidWebUrl("not a url"), false);
});
