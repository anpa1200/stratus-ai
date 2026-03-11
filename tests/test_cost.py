"""
Unit tests for cost estimation in assessment/ai/client.py
"""
import pytest
from assessment.ai.client import estimate_cost


class TestEstimateCost:
    def test_sonnet_cost(self):
        # 1M input + 100k output with Sonnet pricing ($3/$15)
        cost = estimate_cost("claude-sonnet-4-6", 1_000_000, 100_000)
        expected = 3.00 + 15.00 * 0.1  # $3.00 + $1.50 = $4.50
        assert abs(cost - expected) < 0.001

    def test_haiku_cheaper_than_sonnet(self):
        cost_haiku = estimate_cost("claude-haiku-4-5-20251001", 100_000, 10_000)
        cost_sonnet = estimate_cost("claude-sonnet-4-6", 100_000, 10_000)
        assert cost_haiku < cost_sonnet

    def test_opus_most_expensive(self):
        tokens = 100_000
        cost_haiku = estimate_cost("claude-haiku-4-5-20251001", tokens, tokens)
        cost_sonnet = estimate_cost("claude-sonnet-4-6", tokens, tokens)
        cost_opus = estimate_cost("claude-opus-4-6", tokens, tokens)
        assert cost_haiku < cost_sonnet < cost_opus

    def test_zero_tokens(self):
        cost = estimate_cost("claude-sonnet-4-6", 0, 0)
        assert cost == 0.0

    def test_unknown_model_falls_back_to_sonnet(self):
        cost_unknown = estimate_cost("claude-unknown-model", 100_000, 10_000)
        cost_sonnet = estimate_cost("claude-sonnet-4-6", 100_000, 10_000)
        assert cost_unknown == cost_sonnet

    def test_returns_float(self):
        cost = estimate_cost("claude-sonnet-4-6", 5000, 1000)
        assert isinstance(cost, float)

    def test_small_scan_reasonable_cost(self):
        # A typical small scan: ~10k input, ~2k output per module * 9 modules = ~108k input, 18k output
        cost = estimate_cost("claude-sonnet-4-6", 108_000, 18_000)
        # Should be well under $1
        assert cost < 1.0
        assert cost > 0.0
