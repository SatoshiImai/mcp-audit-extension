"""A dummy first-party MCP tool: a research assistant (mirror of the TypeScript tool).

Each internal domain operation is wrapped in the audit-before-act discipline, so the ledger
records what the tool actually did inside -- the tool-internal granularity that boundary-level
audit cannot see.

The three operations deliberately span the (mutates, egress) axis, including the case that
naive "reads are safe" thinking misses: a web search MUTATES NOTHING yet EGRESSES the query.
The secret leaves in the keywords ("AcmeCorp merger due diligence" tells the search provider
you are doing M&A on AcmeCorp) even though nothing comes back changed. That is why egress is
an axis of its own, and why ``api.request`` is not in the benign-read relaxation.
"""

from auditable_mcp.amcp import AmcpSession

SEARCH_ENDPOINT = 'https://api.search.example/v1/search'


class ResearchTool:
    """An in-memory note store plus a web search, all self-attested."""

    def __init__(self, session: AmcpSession) -> None:
        """Bind the audit session and start with no notes."""
        self._session = session
        self._notes: dict[str, dict] = {}
        # end def

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
        # end def

    def save_note(self, topic: str, content: str) -> dict:
        """Persist a note (db.write) -- a state change that stays inside the trust boundary."""

        def perform() -> dict:
            note = {'topic': topic, 'content': content}
            self._notes[topic] = note
            return note
            # end def

        return self._session.audited(
            action_type='db.write',
            target_resource={'kind': 'table', 'ref': 'notes', 'scope_hint': f'topic={topic}'},
            params={'topic': topic, 'content': content},
            perform=perform,
            mutates=True,
            egress=False,
        )
        # end def

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
        # end def

    # end class
