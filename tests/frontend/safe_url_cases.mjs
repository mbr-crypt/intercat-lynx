import { safeHttpUrl } from "../../frontend/lib/safe-url.ts";

const cases = [
  ["https://example.org/a?b=1", "https://example.org/a?b=1"],
  ["http://example.org", "http://example.org/"],
  ["  https://example.org/x  ", "https://example.org/x"],
  ["javascript:alert(1)", undefined],
  ["JaVaScRiPt:alert(1)", undefined],
  [" javascript:alert(1)", undefined],
  ["java\tscript:alert(1)", undefined],
  ["data:text/html;base64,PHNjcmlwdD4=", undefined],
  ["vbscript:x", undefined],
  ["//example.org", undefined],
  ["/relative", undefined],
  ["", undefined],
  [null, undefined],
  [undefined, undefined],
];

let failed = 0;
for (const [input, expected] of cases) {
  const got = safeHttpUrl(input);
  if (got !== expected) {
    failed++;
    console.error(`FAIL safeHttpUrl(${JSON.stringify(input)}) = ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}`);
  }
}
if (failed) process.exit(1);
console.log(`ok ${cases.length}`);
