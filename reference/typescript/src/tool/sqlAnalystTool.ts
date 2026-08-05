import type { AmcpSession } from './amcp.js';

// Example first-party MCP tool: a customer-analysis agent. The host passes a natural-language
// question; the tool's internal agent generates and runs a raw SQL query the host never sees,
// enriches the result through an external geocoding service, then caches it. The three internal
// operations span the (mutates, egress) axis and exercise both confidentiality choices of §4.3:
// the tables touched are disclosed in cleartext while the exact SQL is sealed as a commitment.

export interface AnalysisResult {
  rowCount: number;
}

const CUSTOMER_DB = 'customer-postgres';
const RESULT_TABLE = 'enriched_addresses';
// External geocoding endpoint: the egress destination this tool self-attests and reconciliation
// observes at the boundary (§7.5).
export const GEOCODER = 'https://geo.example/v1/lookup';

export class SqlAnalystTool {
  constructor(private readonly session: AmcpSession) {}

  async analyze(question: string): Promise<AnalysisResult> {
    // The internal agent turns the question into SQL. The host never sees this string.
    const sql = generateSql(question);

    // 1. Read customer rows (incl. postal codes) from the internal DB: no egress. Disclose the
    //    tables touched (routine visibility); seal the exact SQL as a commitment (§4.3).
    const rowCount = await this.session.audited(
      {
        action_type: 'db.query',
        target_resource: { kind: 'database', ref: CUSTOMER_DB },
        effect: { mutates: false, egress: false },
        disclose: { dialect: 'postgres', tables_accessed: ['customers'] },
        commit: sql,
      },
      async () => 42,
    );

    // 2. Enrich the postal codes into addresses via an external geocoding service: the egress.
    await this.session.audited(
      {
        action_type: 'ext.geocode',
        target_resource: { kind: 'endpoint', ref: GEOCODER },
        effect: { mutates: false, egress: true },
        disclose: { provider: 'geo.example' },
      },
      async () => undefined,
    );

    // 3. Persist the enriched rows to an internal table: a mutating write, no egress.
    await this.session.audited(
      {
        action_type: 'db.write',
        target_resource: { kind: 'table', ref: RESULT_TABLE },
        effect: { mutates: true, egress: false },
      },
      async () => undefined,
    );

    return { rowCount };
  }
}

// Stand-in for the internal NL-to-SQL generation the host cannot observe. Deterministic so the
// demo and vectors are reproducible.
function generateSql(_question: string): string {
  return "SELECT id, postal_code FROM customers WHERE city = 'Tokyo' AND ltv > 10000";
}
