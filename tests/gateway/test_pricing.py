"""Cost per run (plan Task 3.9; gateway-design section 9, test CR-1).

`pricing/models.yaml` in the policy bucket gives EUR per million tokens for each model. The estimate
is the agent's own report times those prices: good for budgeting, not for security.
"""

from decimal import Decimal

import pytest

from aiven.gateway.pricing import Pricing, PricingError, Usage

PRICES = b"""\
schema: aiven-pricing/v1
currency: EUR
models:
  gemini-x: {input_per_million: "0.30", output_per_million: "2.50"}
  claude-y: {input_per_million: "3", output_per_million: "15"}
"""


def test_estimate_sums_models():
    # CR-1: every run_end has a cost estimate, summed over every model the run used.
    pricing = Pricing.load(PRICES)
    usage = [
        Usage("gemini-x", input_tokens=1_000_000, output_tokens=200_000),
        Usage("claude-y", input_tokens=10_000, output_tokens=1_000),
        Usage("gemini-x", input_tokens=500_000, output_tokens=0),
    ]
    # 0.30 + 0.50 + 0.03 + 0.015 + 0.15
    assert pricing.estimate(usage) == Decimal("0.995")


def test_missing_model_logs_none_not_error():
    pricing = Pricing.load(PRICES)
    assert pricing.estimate([Usage("unknown-z", 10, 10)]) is None
    assert pricing.estimate([Usage("gemini-x", 10, 10), Usage("unknown-z", 1, 1)]) is None


def test_no_usage_costs_nothing():
    assert Pricing.load(PRICES).estimate([]) == Decimal("0")


def test_an_empty_price_list_estimates_none():
    pricing = Pricing.load(b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {}\n")
    assert pricing.estimate([Usage("gemini-x", 1, 1)]) is None


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfe",
        b"- a list\n",
        b"schema: aiven-pricing/v2\ncurrency: EUR\nmodels: {}\n",
        b"schema: aiven-pricing/v1\ncurrency: USD\nmodels: {}\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: [gemini-x]\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {}\nextra: 1\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {m: {input_per_million: '-1', output_per_million: '1'}}\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {m: {input_per_million: 'x', output_per_million: '1'}}\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {m: {input_per_million: '1'}}\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {m: {input_per_million: '1', output_per_million: '1', x: 1}}\n",
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {m: {input_per_million: 'NaN', output_per_million: '1'}}\n",
    ],
)
def test_a_price_list_that_is_not_v1_is_refused(data):
    with pytest.raises(PricingError):
        Pricing.load(data)


@pytest.mark.parametrize(
    ("model", "inputs", "outputs"),
    [("", 1, 1), ("m", -1, 0), ("m", 0, -1), ("m", True, 0), ("m", 1.5, 0)],
)
def test_usage_is_a_model_and_two_counts(model, inputs, outputs):
    with pytest.raises(ValueError):
        Usage(model, inputs, outputs)


def test_the_repository_price_list_loads():
    from tests.support import REPO_ROOT

    Pricing.load((REPO_ROOT / "pricing" / "models.yaml").read_bytes())
