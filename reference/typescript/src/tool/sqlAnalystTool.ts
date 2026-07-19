import type { AmcpSession } from './amcp.js';

// Example first-party MCP tool: a data-analysis agent. The host passes a natural-language question
// (a host parameter); the tool's internal agent generates and runs a raw SQL query the host never
// sees. Exercises §4.3's two confidentiality choices on a single event: the tables touched are
// disclosed in cleartext for routine visibility, while the exact SQL - which reveals schema and
// the query predicate - is sealed as a commitment, recoverable later from the database's own
// statement log. The question is host-known (recoverable via call_id) and never echoed.

export interface AnalysisResult {
  rowCount: number;
}

const ANALYTICS_DB = 'analytics-postgres';
const RESULT_TABLE = 'analysis_results';

export class SqlAnalystTool {
  constructor(private readonly session: AmcpSession) {}

  async analyze(question: string): Promise<AnalysisResult> {
    // The internal agent turns the question into SQL. The host never sees this string.
    const sql = generateSql(question);

    // 1. Run the SELECT. Disclose the tables touched (coarse, routine visibility) and seal the
    //    exact SQL (forensic non-repudiation); an auditor can reconstruct the hash from the
    //    database's statement log if full-statement logging is enabled.
    const rowCount = await this.session.audited(
      {
        action_type: 'db.query',
        target_resource: { kind: 'database', ref: ANALYTICS_DB },
        effect: { mutates: false, egress: true },
        disclose: { dialect: 'postgres', tables_accessed: ['users', 'payments'] },
        commit: sql,
      },
      async () => 42,
    );

    // 2. Persist the result set locally: a state change inside the trust boundary, with no
    //    internal context worth attesting beyond the target.
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
  return "SELECT email, amount FROM users JOIN payments ON payments.user_id = users.id WHERE users.city = 'Tokyo' AND payments.amount > 10000";
}
