"""Dummy first-party MCP tool (research assistant).

Demonstrates tool-internal domain operations across the (mutates, egress) axis.
Note that web searches are read-only (mutates=False) but leak query parameters (egress=True).
"""

from auditable_mcp.amcp import AmcpSession

SEARCH_ENDPOINT = 'https://api.search.example/v1/search'


class ResearchTool:
    """An in-memory note store plus a web search, all self-attested."""

    def __init__(self, session: AmcpSession) -> None:
        """Bind the audit session and start with no notes."""
        self._session = session
        self._notes: dict[str, dict] = {}

    def search(self, query: str) -> list[dict]:
        """Search the web (api.request).

        Mutates nothing, but the query egresses. The query is hashed into params_hash and
        never stored raw: it is precisely the sensitive part that leaked.
        """
        return self._session.audited(
            action_type='api.request',
            target_resource={'kind': 'endpoint', 'ref': SEARCH_ENDPOINT},
            params={'query': query},
            perform=lambda: [{'title': f'Result for {query}', 'url': 'https://example.com/a'}],
            mutates=False,
            egress=True,
        )

    def save_note(self, topic: str, content: str) -> dict:
        """Persist a note (db.write) -- a state change that stays inside the trust boundary."""

        def perform() -> dict:
            note = {'topic': topic, 'content': content}
            self._notes[topic] = note
            return note

        return self._session.audited(
            action_type='db.write',
            target_resource={'kind': 'table', 'ref': 'notes', 'scope_hint': f'topic={topic}'},
            params={'topic': topic, 'content': content},
            perform=perform,
            mutates=True,
            egress=False,
        )

    def list_notes(self) -> list[dict]:
        """List notes (db.read) -- the genuinely benign case: no state change, no egress."""
        return self._session.audited(
            action_type='db.read',
            target_resource={'kind': 'table', 'ref': 'notes'},
            params={},
            perform=lambda: list(self._notes.values()),
            mutates=False,
            egress=False,
        )
