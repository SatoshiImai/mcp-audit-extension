import type { AmcpSession } from './amcp.js';

// Dummy first-party MCP tool (research assistant). Its three operations span the
// (mutates, egress) axis. A web search is read-only (mutates=false) but leaks its query
// parameters (egress=true).

export interface Note {
  topic: string;
  content: string;
}

export interface SearchHit {
  title: string;
  url: string;
}

const SEARCH_ENDPOINT = 'https://api.search.example/v1/search';

export class ResearchTool {
  private readonly notes = new Map<string, Note>();

  constructor(private readonly session: AmcpSession) {}

  // api.request: mutates nothing, but the query egresses. The query is hashed into
  // params_hash, never stored raw.
  async search(query: string): Promise<SearchHit[]> {
    return this.session.audited(
      {
        action_type: 'api.request',
        target_resource: { kind: 'endpoint', ref: SEARCH_ENDPOINT },
        params: { query },
        effect: { mutates: false, egress: true },
      },
      async () => [{ title: `Result for ${query}`, url: 'https://example.com/a' }],
    );
  }

  // db.write: a state change inside the trust boundary.
  async saveNote(topic: string, content: string): Promise<Note> {
    return this.session.audited(
      {
        action_type: 'db.write',
        target_resource: { kind: 'table', ref: 'notes', scope_hint: `topic=${topic}` },
        params: { topic, content },
        effect: { mutates: true, egress: false },
      },
      async () => {
        const note: Note = { topic, content };
        this.notes.set(topic, note);
        return note;
      },
    );
  }

  // db.read: no state change, no egress.
  async listNotes(): Promise<Note[]> {
    return this.session.audited(
      {
        action_type: 'db.read',
        target_resource: { kind: 'table', ref: 'notes' },
        params: {},
        effect: { mutates: false, egress: false },
      },
      async () => [...this.notes.values()],
    );
  }
}
