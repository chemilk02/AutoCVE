"""모델별 단가표 (USD / 1M 토큰). 단가가 바뀌면 이 표만 고친다.

Anthropic 단가는 공개 단가표 기준이다. 캐시 쓰기는 5분 TTL 기준 입력 단가의 1.25배로 잡았다.
캐시 읽기 단가가 공개 자료에 없는 모델은 입력 단가의 0.1배로 잡았다 (확인 필요).
JEV(TypeSafe 직접)는 입력만 과금된다. OpenRouter 경유 단가는 확인 전이라 같은 값을 쓴다.
"""

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class Price:
    input: Decimal
    output: Decimal
    cache_write: Decimal
    cache_read: Decimal


def _anthropic(inp: str, out: str, cache_read: str | None = None) -> Price:
    i = Decimal(inp)
    return Price(
        input=i,
        output=Decimal(out),
        cache_write=i * Decimal("1.25"),
        cache_read=Decimal(cache_read) if cache_read else i * Decimal("0.1"),
    )


_JEV = Price(Decimal("0.042"), Decimal(0), Decimal(0), Decimal(0))

PRICES: dict[tuple[str, str], Price] = {
    ("anthropic", "claude-haiku-5-5"): _anthropic("0.10", "0.50"),
    ("anthropic", "claude-sonnet-5-5"): _anthropic("2", "10", "0.20"),
    ("anthropic", "claude-opus-5-5"): _anthropic("4", "20", "0.20"),
}

MILLION = Decimal(1_000_000)


def price_for(provider: str, model: str) -> Price | None:
    if provider in ("typesafe", "openrouter"):
        return _JEV
    return PRICES.get((provider, model))


def cost_usd(
    provider: str,
    model: str,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
) -> Decimal:
    price = price_for(provider, model)
    if price is None:
        return Decimal(0)
    total = (
        price.input * input_tokens
        + price.output * output_tokens
        + price.cache_write * cache_creation_input_tokens
        + price.cache_read * cache_read_input_tokens
    )
    return (total / MILLION).quantize(Decimal("0.000001"))
