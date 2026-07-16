import type { AmcpSession } from './amcp.js';

// A dummy first-party MCP tool: a customer database. Each internal domain operation is
// wrapped in the audit-before-act discipline, so the ledger records what the tool actually
// did inside — the tool-internal granularity that boundary-level audit (SEP-3004, gateways)
// cannot see. Being first-party, its effect declarations are trusted (Level 1).

export interface Customer {
  id: string;
  name: string;
  email: string;
}

export class CustomerDbTool {
  private readonly store = new Map<string, Customer>();

  constructor(private readonly session: AmcpSession) {
    this.store.set('c_1', { id: 'c_1', name: 'Acme Co', email: 'ops@acme.example' });
    this.store.set('c_2', { id: 'c_2', name: 'Globex', email: 'it@globex.example' });
  }

  async getCustomer(customerId: string): Promise<Customer | undefined> {
    return this.session.audited(
      {
        action_type: 'db.read',
        target_resource: { kind: 'table', ref: 'customers', scope_hint: `row:id=${customerId}` },
        params: { customerId },
        effect: { mutates: false, egress: false },
      },
      async () => this.store.get(customerId),
    );
  }

  async updateEmail(customerId: string, email: string): Promise<Customer> {
    return this.session.audited(
      {
        action_type: 'db.write',
        target_resource: { kind: 'table', ref: 'customers', scope_hint: `row:id=${customerId}` },
        params: { customerId, email },
        effect: { mutates: true, egress: false },
      },
      async () => {
        const existing = this.store.get(customerId);
        if (!existing) throw new Error(`customer ${customerId} not found`);
        const updated: Customer = { ...existing, email };
        this.store.set(customerId, updated);
        return updated;
      },
    );
  }
}
