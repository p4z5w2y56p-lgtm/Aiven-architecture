"""Cost per run (plan Task 3.9; gateway-design section 9, test CR-1).

`pricing/models.yaml` (in the policy bucket, written by Matthijs) lists EUR per million input and
output tokens for each model, as exact decimals. When a run ends, the agent reports its usage, and
`Pricing.estimate` turns it into euros. A model without a price gives no estimate (None), never an
error and never a guess: the shadow review then shows "unknown" for that run.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

SCHEMA = "aiven-pricing/v1"
MILLION = Decimal(1_000_000)


class PricingError(ValueError):
    """The price list is not a valid `aiven-pricing/v1` document."""


@dataclass(frozen=True)
class Usage:
    """What a run used of one model, as the agent reports it (section 4, `:end`)."""

    model: str
    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        if not (isinstance(self.model, str) and self.model):
            raise ValueError("usage needs the model")
        for count in (self.input_tokens, self.output_tokens):
            if type(count) is not int or count < 0:
                raise ValueError("token counts are whole numbers of 0 or more")


@dataclass(frozen=True)
class Price:
    input_per_million: Decimal
    output_per_million: Decimal


def _price(value: object, model: str) -> Price:
    if not isinstance(value, dict) or set(value) != {"input_per_million", "output_per_million"}:
        raise PricingError(f"model {model!r} needs input_per_million and output_per_million only")
    amounts = []
    for name in ("input_per_million", "output_per_million"):
        try:
            amount = Decimal(str(value[name]))
        except InvalidOperation as error:
            raise PricingError(f"model {model!r}: {name} is not a number") from error
        if not amount.is_finite() or amount < 0:
            raise PricingError(f"model {model!r}: {name} must be 0 or more")
        amounts.append(amount)
    return Price(*amounts)


@dataclass(frozen=True)
class Pricing:
    prices: dict[str, Price]

    @classmethod
    def load(cls, data: bytes) -> "Pricing":
        """The price list in `data`. Raises PricingError for anything but valid v1."""
        try:
            doc: Any = YAML(typ="safe").load(data.decode("utf-8"))
        except (UnicodeDecodeError, YAMLError) as error:
            raise PricingError("the price list is not UTF-8 YAML") from error
        if not isinstance(doc, dict) or set(doc) != {"schema", "currency", "models"}:
            raise PricingError("the price list has schema, currency and models, and nothing else")
        if doc["schema"] != SCHEMA:
            raise PricingError(f"the price list's schema must be {SCHEMA}")
        if doc["currency"] != "EUR":
            raise PricingError("prices are in EUR")
        if not isinstance(doc["models"], dict):
            raise PricingError("models is a mapping of model to prices")
        return cls({str(model): _price(value, model) for model, value in doc["models"].items()})

    def estimate(self, usage: Iterable[Usage]) -> Decimal | None:
        """The cost of `usage` in EUR, or None when a model has no price."""
        total = Decimal(0)
        for used in usage:
            price = self.prices.get(used.model)
            if price is None:
                return None
            total += used.input_tokens * price.input_per_million / MILLION
            total += used.output_tokens * price.output_per_million / MILLION
        return total
