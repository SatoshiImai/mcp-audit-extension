"""Example first-party MCP tool: a data-analysis agent.

The host passes a natural-language question (a host parameter); the tool's internal agent
generates and runs a raw SQL query the host never sees. Exercises §4.3's two confidentiality
choices on a single event: the tables touched are disclosed in cleartext for routine visibility,
while the exact SQL -- which reveals schema and the query predicate -- is sealed as a commitment,
recoverable later from the database's own statement log. The question is host-known (recoverable
via call_id) and never echoed.
"""

from auditable_mcp.amcp import AmcpSession

ANALYTICS_DB = 'analytics-postgres'
RESULT_TABLE = 'analysis_results'


class SqlAnalystTool:
    """A data-analysis agent that self-attests the SQL query it runs internally."""

    def __init__(self, session: AmcpSession) -> None:
        """Bind the audit session."""
        self._session = session

    def analyze(self, question: str) -> dict:
        """Answer a question by running an internally generated SQL query.

        Runs a SELECT that discloses the tables touched and seals the exact SQL, then caches the
        result inside the trust boundary.

        Args:
            question: The host's natural-language question.

        Returns:
            A dict with the number of rows returned.
        """
        sql = _generate_sql(question)
        row_count = self._session.audited(
            'db.query',
            {'kind': 'database', 'ref': ANALYTICS_DB},
            lambda: 42,
            mutates=False,
            egress=True,
            disclose={'dialect': 'postgres', 'tables_accessed': ['users', 'payments']},
            commit=sql,
        )
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
    return (
        'SELECT email, amount FROM users JOIN payments ON payments.user_id = users.id '
        "WHERE users.city = 'Tokyo' AND payments.amount > 10000"
    )
