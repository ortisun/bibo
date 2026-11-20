// Syntax-checks every ```mermaid block in the given Markdown files with Mermaid's own parser.
// It checks syntax only. It does not render, so it cannot judge layout or readability.
//
//   docs/architecture/tools/check-mermaid.sh <file.md> [<file.md> ...]
//
// Run it through check-mermaid.sh. The script installs the pinned packages into a temporary
// directory so no node_modules folder appears in the repository.
//
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
const dom = new JSDOM('<!doctype html><html><body></body></html>', { pretendToBeVisual: true });
globalThis.window = dom.window; globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true });
const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false });
let failed = 0, total = 0;
for (const file of process.argv.slice(2)) {
  const text = readFileSync(file, 'utf8');
  const blocks = [...text.matchAll(/```mermaid\n([\s\S]*?)```/g)].map(m => m[1]);
  for (const [i, src] of blocks.entries()) {
    total++;
    try { const r = await mermaid.parse(src); console.log(`ok    ${file} block ${i + 1} (${r.diagramType})`); }
    catch (e) { failed++; console.log(`FAIL  ${file} block ${i + 1}: ${String(e.message || e).split('\n').slice(0, 3).join(' | ')}`); }
  }
}
console.log(`${total - failed}/${total} mermaid blocks parse`);
process.exit(failed ? 1 : 0);
