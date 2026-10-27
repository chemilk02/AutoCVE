"""판별 입력.

규칙 기반 판별은 필드를 직접 보고, JEV에는 `render_state()`로 만든 짧은 텍스트를 보낸다.
"""

from dataclasses import dataclass, field

from autocve.triage.evidence import Evidence

# JEV 단가는 입력에만 붙는다. 목표는 4K 토큰 이하 (글자 수로 대략 4배).
MAX_STATE_CHARS = 16_000
STATE_SNIPPETS = 3


@dataclass
class TriageInput:
    finding_id: int
    advisory_id: str
    summary: str
    package: str  # purl
    direct: bool
    scope: str
    cvss: float | None
    epss: float | None
    in_kev: bool
    attack_vector: str | None
    malicious: bool
    profile: dict = field(default_factory=dict)
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def severe(self) -> bool:
        return self.in_kev or (self.cvss is not None and self.cvss >= 9.0)

    def render_state(self, snippets: int = STATE_SNIPPETS) -> str:
        profile = self.profile or {}
        ev = self.evidence
        lines = [
            "[vulnerability]",
            f"id: {self.advisory_id}",
            f"summary: {self.summary}",
            f"vulnerable_symbols: {', '.join(profile.get('vulnerable_symbols') or []) or 'none'}",
            f"requires_specific_api: {profile.get('requires_specific_api', 'unknown')}",
            f"trigger: {profile.get('trigger_conditions') or 'unknown'}",
            f"preconditions: {'; '.join(profile.get('preconditions') or []) or 'none'}",
            "[signals]",
            f"cvss: {self.cvss if self.cvss is not None else 'unknown'}",
            f"epss: {self.epss if self.epss is not None else 'unknown'}",
            f"known_exploited: {self.in_kev}",
            f"attack_vector: {self.attack_vector or profile.get('attack_vector') or 'unknown'}",
            "[component]",
            f"package: {self.package}",
            f"dependency: {'direct' if self.direct else 'transitive'}, {self.scope}",
            "[evidence]",
            f"prod_files_importing_package: {len(ev.prod_import_files)}",
            f"test_files_importing_package: {len(ev.test_import_files)}",
            f"symbol_matches_in_prod_code: {ev.call_site_count}"
            + ("" if ev.checkout_available else " (code not inspected)"),
        ]
        for snippet in ev.snippets[:snippets]:
            lines += [f"--- {snippet.path}:{snippet.line} ({snippet.symbol})", snippet.code]
        text = "\n".join(lines)
        if len(text) > MAX_STATE_CHARS and snippets > 0:
            return self.render_state(snippets - 1)
        return text[:MAX_STATE_CHARS]
