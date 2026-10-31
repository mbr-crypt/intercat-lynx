// Run by tests/test_safe_next.py: node --experimental-strip-types tests/frontend/safe_next_cases.mjs
import { safeNext } from "../../frontend/lib/authed-fetch.ts";

const cases = [
  // [input, expected]
  ["/", "/"],
  ["/news", "/news"],
  ["/vulnerabilities/CVE-2024-1?tab=2#x", "/vulnerabilities/CVE-2024-1?tab=2#x"],
  [null, "/"],
  [undefined, "/"],
  ["", "/"],
  ["news", "/"],
  ["https://evil.example/", "/"],
  ["//evil.example", "/"],
  ["/\\evil.example", "/"],
  ["/\t/evil.example", "/"], // browsers drop the TAB: this was the open redirect
  ["/\n/evil.example", "/"],
  ["/\r/evil.example", "/"],
  ["/\u0000/evil.example", "/"],
  ["/news\t", "/"],
  ["/auth", "/"],
  ["/auth?next=/x", "/"],
  ["/setup", "/"],
  ["/setup/step", "/"],
];

let failed = 0;
for (const [input, expected] of cases) {
  const got = safeNext(input);
  if (got !== expected) {
    failed++;
    console.error(`FAIL safeNext(${JSON.stringify(input)}) = ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}`);
  }
}
if (failed) process.exit(1);
console.log(`ok ${cases.length}`);
