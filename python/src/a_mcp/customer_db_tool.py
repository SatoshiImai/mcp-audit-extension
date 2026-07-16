"""A dummy first-party MCP tool: a customer database (mirror of the TypeScript tool).

Each internal domain operation is wrapped in the audit-before-act discipline, so the ledger
records what the tool actually did inside -- the tool-internal granularity that boundary-level
audit cannot see. Being first-party, its effect declarations are trusted (Level 1).
"""

from a_mcp.amcp import AmcpSession


class CustomerDbTool:
    """An in-memory customer store whose internal reads/writes are self-attested."""

    def __init__(self, session: AmcpSession) -> None:
        """Seed the store and bind the audit session."""
        self._session = session
        self._store: dict[str, dict] = {
            'c_1': {'id': 'c_1', 'name': 'Acme Co', 'email': 'ops@acme.example'},
            'c_2': {'id': 'c_2', 'name': 'Globex', 'email': 'it@globex.example'},
        }
        # end def

    def get_customer(self, customer_id: str) -> dict | None:
        """Read a customer (db.read)."""
        return self._session.audited(
            action_type='db.read',
            target_resource={'kind': 'table', 'ref': 'customers', 'scope_hint': f'row:id={customer_id}'},
            params={'customerId': customer_id},
            perform=lambda: self._store.get(customer_id),
            mutates=False,
            egress=False,
        )
        # end def

    def update_email(self, customer_id: str, email: str) -> dict:
        """Update a customer email (db.write)."""

        def perform() -> dict:
            existing = self._store.get(customer_id)
            if existing is None:
                raise ValueError(f'customer {customer_id} not found')
                # end if
            updated = {**existing, 'email': email}
            self._store[customer_id] = updated
            return updated
            # end def

        return self._session.audited(
            action_type='db.write',
            target_resource={'kind': 'table', 'ref': 'customers', 'scope_hint': f'row:id={customer_id}'},
            params={'customerId': customer_id, 'email': email},
            perform=perform,
            mutates=True,
            egress=False,
        )
        # end def

    # end class
