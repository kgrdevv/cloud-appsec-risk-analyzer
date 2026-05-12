from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class NormalizedFinding:
    scanner: str
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    end_line: int | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    confidence: str | None = None
    impact: str | None = None
    likelihood: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScoredFinding:
    scanner: str
    rule_id: str
    title: str
    severity: str
    priority: str
    risk_score: int
    category: str
    file: str
    line: int
    end_line: int | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    confidence: str | None = None
    impact: str | None = None
    likelihood: str | None = None
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
