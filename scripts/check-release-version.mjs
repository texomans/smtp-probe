// Run before publishing so the container tag agrees with its runtime version.
import { readFileSync } from 'node:fs';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const tag = process.argv[2];
const expected = `v${version}`;

if (tag !== expected) {
  console.error(`Release tag ${JSON.stringify(tag ?? '')} does not match package.json; expected ${expected}.`);
  process.exitCode = 1;
} else {
  console.log(`Release tag matches package.json: ${expected}`);
}
