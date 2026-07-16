import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Language-neutral spec artifacts live at the repo root under spec/, so the TypeScript and
// Python reference implementations validate against the SAME JSON Schema and conformance
// vectors. Resolve them relative to this file (typescript/src/), never the cwd.
const HERE = dirname(fileURLToPath(import.meta.url)); // typescript/src
const REPO_ROOT = resolve(HERE, '..', '..'); // repo root

export const SPEC_SCHEMA_DIR = resolve(REPO_ROOT, 'spec', 'schema');
export const SPEC_VECTORS_DIR = resolve(REPO_ROOT, 'spec', 'vectors');
