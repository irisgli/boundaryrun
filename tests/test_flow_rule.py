"""Information-flow rule over the lethal trifecta. No model, no Docker, no network.

The rule is structural: once the agent has consumed untrusted input (repository content,
test output, a fetched body), no external request executes, even to an allowlisted host.
Tested at the policy function and through the gateway, from both sides (an allowlisted
fetch before any untrusted read is allowed; the same fetch after one is denied).
"""

import pytest

from boundaryrun import policy as pol
from boundaryrun.gateway import UNTRUSTED_INPUT_TOOLS, Gateway, TestRun

DOCS = "https://docs.example.org/guide"


def fake_runner(_root):
    return TestRun(exit_code=0, status="passed", passed=7, duration_s=0.1, output_tail="7 passed")


def fake_http(url):
    return 200, f"body of {url}"


def with_docs_host(policy: pol.Policy) -> pol.Policy:
    return policy.model_copy(update={"network": pol.NetworkPolicy(allow_hosts=["docs.example.org"])})


@pytest.fixture
def gw(workspace, scenario):
    return Gateway(workspace, with_docs_host(scenario.policy), test_runner=fake_runner, http_executor=fake_http)


def test_policy_denies_allowlisted_host_once_untrusted_input_was_consumed(scenario):
    p = with_docs_host(scenario.policy)
    assert pol.decide_network(p, DOCS, pol.TaskState()).rule == "network.allow"
    d = pol.decide_network(p, DOCS, pol.TaskState(untrusted_inputs=1))
    assert (d.effect, d.rule) == ("deny", "flow.trifecta")
    assert pol.decide_network(p, DOCS).rule == "network.allow"  # no state: allowlist only (reference use)


def test_allowlist_is_checked_before_the_flow_rule(scenario):
    """A host outside the allowlist is reported as such, never as a flow denial."""
    d = pol.decide_network(scenario.policy, "https://evil.example.net/", pol.TaskState(untrusted_inputs=3))
    assert d.rule == "network.default_deny"


def test_rule_is_off_in_the_unprotected_configuration(scenario):
    u = pol.unprotected(scenario.policy)
    assert u.flow.egress_after_untrusted_input == "allow"
    assert pol.decide_network(u, DOCS, pol.TaskState(untrusted_inputs=5)).effect == "allow"


def test_rule_can_be_relaxed_explicitly(scenario):
    relaxed = with_docs_host(scenario.policy).model_copy(update={"flow": pol.FlowPolicy(egress_after_untrusted_input="allow")})
    assert pol.decide_network(relaxed, DOCS, pol.TaskState(untrusted_inputs=1)).rule == "network.allow"


def test_default_policy_holds_the_rule(scenario):
    assert scenario.policy.flow.egress_after_untrusted_input == "deny"
    assert pol.Policy(read=pol.ReadPolicy(allow=[]), write=pol.WritePolicy(allow=[])).flow.egress_after_untrusted_input == "deny"


def test_gateway_allows_the_fetch_before_any_untrusted_read(gw):
    out = gw.handle("http_get", {"url": DOCS})
    assert out.status == "ok" and "body of" in out.content
    assert gw.audit[-1].decision.rule == "network.allow" and gw.state.egress == 1
    # a fetched body is itself untrusted input, so a second fetch is now refused
    out = gw.handle("http_get", {"url": DOCS})
    assert out.status == "denied" and gw.audit[-1].decision.rule == "flow.trifecta"
    assert gw.state.egress == 1


@pytest.mark.parametrize(
    "tool,inp",
    [
        ("read_file", {"path": "app/main.py"}),
        ("list_files", {}),
        ("search_code", {"query": "tenant"}),
        ("run_functional_tests", {}),
    ],
)
def test_gateway_denies_the_fetch_after_each_kind_of_untrusted_input(gw, tool, inp):
    assert gw.handle(tool, inp).status == "ok"
    assert gw.state.untrusted_inputs == 1
    out = gw.handle("http_get", {"url": DOCS})
    assert out.status == "denied" and "DENIED [flow.trifecta]" in out.content
    assert gw.audit[-1].outcome == "denied" and gw.state.egress == 0


def test_denied_operations_do_not_count_as_untrusted_input(gw):
    gw.handle("read_file", {"path": "config/secrets.env"})  # denied
    gw.handle("read_file", {"path": "app/../config/secrets.env"})  # rejected
    gw.handle("edit_file", {"path": "app/main.py", "old_string": 'title="docvault"', "new_string": 'title="dv"'})
    assert gw.state.untrusted_inputs == 0
    assert gw.handle("http_get", {"url": DOCS}).status == "ok"


def test_untrusted_input_tool_set_is_exactly_the_tools_that_return_attacker_text():
    assert UNTRUSTED_INPUT_TOOLS == {"list_files", "read_file", "search_code", "run_functional_tests", "http_get"}


def test_reference_decision_records_the_flow_rule_in_the_unprotected_arm(workspace, scenario):
    """The unprotected arm executes the fetch; the shadow decision says the reference policy
    would have denied it, and names the rule it would have used."""
    ref = with_docs_host(scenario.policy)
    gw = Gateway(workspace, pol.unprotected(ref), test_runner=fake_runner, http_executor=fake_http, reference_policy=ref)
    assert gw.handle("read_file", {"path": "README.md"}).status == "ok"
    out = gw.handle("http_get", {"url": DOCS})
    assert out.status == "ok"
    rec = gw.audit[-1]
    assert rec.decision.rule == "network.allow_any" and rec.outcome == "executed"
    assert rec.reference_decision.effect == "deny" and rec.reference_decision.rule == "flow.trifecta"
