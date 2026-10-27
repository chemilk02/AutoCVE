"""판별 모델 (§4.3). 두 질문을 묻는다: 영향 여부(`exposure`)와 분석 경로(`analysis_route`).

- `SystemOneTriage`: TypeSafe JEV. TypeSafe 직접 호출과 OpenRouter 경유가 같은 `systemone` 형식이다.
- `RuleTriage`: JEV 키가 없거나 호출이 실패했을 때 쓰는 규칙 기반 판별. 자동 종결은 하지 않는다.

JEV 요청·응답 형식은 서드파티 자료로만 확인했다 (docs/02-architecture.md §4.6).
응답 파싱은 필드 이름이 조금 달라도 동작하도록 느슨하게 했다.
"""

from dataclasses import dataclass, field
from typing import Protocol

import httpx

from autocve.triage.inputs import TriageInput

EXPOSURE = "exposure"
ROUTE = "analysis_route"

EXPOSURE_OPTIONS = {
    "not_affected": (
        "The codebase cannot reach the vulnerable behavior: the package is not used by "
        "production code, or the vulnerable API and conditions are clearly absent."
    ),
    "possibly_affected": (
        "Reachability is unclear from the evidence: the package is used but it is not visible "
        "whether the vulnerable API or conditions are involved."
    ),
    "likely_affected": (
        "Production code uses the vulnerable API or the vulnerability applies to every use of "
        "the package, so an attacker can probably reach it."
    ),
}

ROUTE_OPTIONS = {
    "no_llm": (
        "No further analysis is needed: the evidence is unambiguous, such as the package not "
        "being imported anywhere in production code."
    ),
    "haiku": (
        "A quick check of the given snippets is enough: few call sites (three or fewer) and "
        "simple trigger conditions."
    ),
    "sonnet": (
        "Data flow must be followed across several files to decide whether untrusted input "
        "reaches the vulnerable call."
    ),
    "opus": (
        "Complex conditions such as configuration, authentication paths or framework internals "
        "decide reachability, and the severity makes a wrong answer costly."
    ),
}

QUESTIONS = {
    EXPOSURE: {
        "type": "choice",
        "instructions": "Decide whether this codebase is affected by the vulnerability.",
        "options": EXPOSURE_OPTIONS,
    },
    ROUTE: {
        "type": "choice",
        "instructions": "Choose the cheapest analysis that can settle the question reliably.",
        "options": ROUTE_OPTIONS,
    },
}


class TriageError(Exception):
    pass


@dataclass
class Judgement:
    exposure_probs: dict[str, float]
    route_probs: dict[str, float]
    confidence: float
    provider: str
    model_version: str | None = None
    input_tokens: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def exposure(self) -> str:
        return max(self.exposure_probs, key=self.exposure_probs.get)

    @property
    def route(self) -> str:
        return max(self.route_probs, key=self.route_probs.get)


class TriageModel(Protocol):
    def judge(self, inp: TriageInput, *, include_snippets: bool = True) -> Judgement: ...


def _normalize(probs: dict, options: dict) -> dict[str, float]:
    cleaned = {k: float(v) for k, v in (probs or {}).items() if k in options}
    total = sum(cleaned.values())
    if not cleaned or total <= 0:
        raise TriageError("확률 분포가 비어 있습니다")
    return {k: cleaned.get(k, 0.0) / total for k in options}


def parse_systemone_response(data: dict) -> tuple[dict, dict, float]:
    answers = data.get("answers") or data.get("results") or data
    try:
        exposure = answers[EXPOSURE]
        route = answers[ROUTE]
    except (KeyError, TypeError) as e:
        raise TriageError("응답에 판별 결과가 없습니다") from e
    exposure_probs = _normalize(exposure.get("probabilities"), EXPOSURE_OPTIONS)
    route_probs = _normalize(route.get("probabilities"), ROUTE_OPTIONS)
    confidence = exposure.get("confidence")
    if confidence is None:
        confidence = max(exposure_probs.values())
    return exposure_probs, route_probs, float(confidence)


class SystemOneTriage:
    def __init__(
        self,
        provider: str,
        base_url: str,
        api_key: str,
        model: str,
        http: httpx.Client | None = None,
    ):
        self.provider = provider
        self._url = f"{base_url.rstrip('/')}/systemone"
        self._key = api_key
        self._model = model
        self._http = http or httpx.Client(timeout=30.0)

    def judge(self, inp: TriageInput, *, include_snippets: bool = True) -> Judgement:
        state = inp.render_state() if include_snippets else inp.render_state(snippets=0)
        body = {"model": self._model, "state": state, "questions": QUESTIONS}
        try:
            response = self._http.post(
                self._url, json=body, headers={"Authorization": f"Bearer {self._key}"}
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as e:
            raise TriageError(f"JEV 호출 실패: {type(e).__name__}") from e
        exposure_probs, route_probs, confidence = parse_systemone_response(data)
        usage = data.get("usage") or {}
        return Judgement(
            exposure_probs=exposure_probs,
            route_probs=route_probs,
            confidence=confidence,
            provider=self.provider,
            model_version=data.get("model") or self._model,
            # 응답에 사용량이 없으면 글자 수로 어림한다.
            input_tokens=int(usage.get("input_tokens") or len(state) // 4),
        )


def _one_hot(options: dict, chosen: str, weight: float) -> dict[str, float]:
    rest = (1.0 - weight) / (len(options) - 1)
    return {k: (weight if k == chosen else rest) for k in options}


class RuleTriage:
    """보수적인 규칙.

    코드 인덱스만으로는 영향이 없다고 단정할 근거가 부족해서 자동 종결(no_llm)은 고르지 않는다.
    """

    provider = "rules"

    def judge(self, inp: TriageInput, *, include_snippets: bool = True) -> Judgement:
        ev = inp.evidence
        profile = inp.profile or {}
        symbols = profile.get("vulnerable_symbols") or []
        specific = bool(profile.get("requires_specific_api")) and bool(symbols)
        reasons: list[str] = []

        if not ev.prod_import_files:
            if inp.direct:
                exposure, weight = "not_affected", 0.75
                reasons.append("직접 의존성이지만 prod 코드에서 import하지 않음")
            else:
                exposure, weight = "possibly_affected", 0.5
                reasons.append("간접 의존성이라 상위 패키지를 통해 쓰일 수 있음")
            route = "haiku"
        elif specific and ev.checkout_available and ev.call_site_count == 0:
            exposure, weight, route = "not_affected", 0.7, "haiku"
            reasons.append("import하지만 취약 API가 코드에 보이지 않음")
        elif specific and ev.call_site_count > 0:
            exposure, weight = "likely_affected", 0.7
            route = "haiku" if ev.call_site_count <= 3 else "sonnet"
            reasons.append(f"취약 API 사용 위치 {ev.call_site_count}곳")
        else:
            # 판단 근거가 적을 때는 싼 모델로 먼저 보고, 불확실하면 분석 단계에서 올린다.
            exposure, weight, route = "possibly_affected", 0.6, "haiku"
            reasons.append("특정 API와 무관한 취약점이거나 API 정보가 없음")

        return Judgement(
            exposure_probs=_one_hot(EXPOSURE_OPTIONS, exposure, weight),
            route_probs=_one_hot(ROUTE_OPTIONS, route, 0.7),
            confidence=weight,
            provider=self.provider,
            reasons=reasons,
        )
