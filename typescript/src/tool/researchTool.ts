import type { AmcpSession } from './amcp.js';

// A dummy first-party MCP tool: a research assistant. Each internal domain operation is
// wrapped in the audit-before-act discipline, so the ledger records what the tool actually
// did inside — the tool-internal granularity that boundary-level audit cannot see.
//
// The three operations deliberately span the (mutates, egress) axis, including the case that
// naive "reads are safe" thinking misses: a web search MUTATES NOTHING yet EGRESSES the
// query. The secret leaves in the keywords ("AcmeCorp merger due diligence" tells the search
// provider you are doing M&A on AcmeCorp) even though nothing comes back changed. That is why
// egress is an axis of its own, and why `api.request` is not in the benign-read relaxation.

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

  // api.request — mutates nothing, but the query egresses. The query is hashed into
  // params_hash and never stored raw: it is precisely the sensitive part that leaked.
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

  // db.write — a state change that stays inside the trust boundary.
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

  // db.read — the genuinely benign case: no state change, no egress.
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
