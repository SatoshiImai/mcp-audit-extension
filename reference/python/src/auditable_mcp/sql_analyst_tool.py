"""Example first-party MCP tool: a customer-analysis agent.

The host passes a natural-language question; the tool's internal agent generates and runs a raw SQL
query the host never sees, enriches the result through an external geocoding service, then caches
it. The three internal operations span the (mutates, egress) axis and exercise both confidentiality
choices of §4.3: the tables touched are disclosed in cleartext while the exact SQL is sealed as a
commitment, recoverable later from the database's own statement log.
"""

from auditable_mcp.amcp import AmcpSession

CUSTOMER_DB = 'customer-postgres'
RESULT_TABLE = 'enriched_addresses'
# External geocoding endpoint: the egress destination this tool self-attests and reconciliation
# observes at the boundary (§7.5).
GEOCODER = 'https://geo.example/v1/lookup'


class SqlAnalystTool:
    """A data-analysis agent that self-attests the operations it runs internally."""

    def __init__(self, session: AmcpSession) -> None:
        """Bind the audit session."""
        self._session = session

    def analyze(self, question: str) -> dict:
        """Answer a question: query the internal DB, enrich via an external geocoder, cache the result.

        Args:
            question: The host's natural-language question.

        Returns:
            A dict with the number of rows returned.
        """
        sql = _generate_sql(question)
        # 1. Read customer rows (incl. postal codes) from the internal DB: no egress. Disclose the
        #    tables touched; seal the exact SQL as a commitment (§4.3).
        row_count = self._session.audited(
            'db.query',
            {'kind': 'database', 'ref': CUSTOMER_DB},
            lambda: 42,
            mutates=False,
            egress=False,
            disclose={'dialect': 'postgres', 'tables_accessed': ['customers']},
            commit=sql,
        )
        # 2. Enrich the postal codes into addresses via an external geocoding service: the egress.
        self._session.audited(
            'ext.geocode',
            {'kind': 'endpoint', 'ref': GEOCODER},
            lambda: None,
            mutates=False,
            egress=True,
            disclose={'provider': 'geo.example'},
        )
        # 3. Persist the enriched rows to an internal table: a mutating write, no egress.
        self._session.audited(
            'db.write',
            {'kind': 'table', 'ref': RESULT_TABLE},
            lambda: None,
            mutates=True,
            egress=False,
        )
        return {'row_count': row_count}


def _generate_sql(question: str) -> str:
    """Stand-in for the internal NL-to-SQL generation the host cannot observe.

    Deterministic so the demo and vectors are reproducible.

    Args:
        question: The host's natural-language question (ignored by this stub).

    Returns:
        A fixed SQL query string.
    """
    del question
    return "SELECT id, postal_code FROM customers WHERE city = 'Tokyo' AND ltv > 10000"
