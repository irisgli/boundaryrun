"""Information-flow rule over the lethal trifecta. No model and no Docker.

An allowlisted host is reachable until the agent has consumed untrusted input (repository
content, test output or a fetched body). After that the same request is denied with
`flow.trifecta`, whatever the allowlist says. Hosts outside the allowlist are denied by the
allowlist rule, never by the flow rule, so the flow rule is only ever the reason when the
host would otherwise have been allowed.
"""

import pytest

from boundaryrun import policy as pol
from boundaryrun.gateway import Gateway
from boundaryrun.pipeline import InjectionObservation, _observe_flow

HOST = "docs.example.org"


def fake_http(url: str) -> tuple[int, str]:
    return 200, f"fetched {url}"


@pytest.fixture
def allowlisted(scenario):
    net = pol.NetworkPolicy(allow_hosts=[HOST])
    return scenario.policy.model_copy(update={"network": net})


def test_policy_has_flow_rule_on_by_default(scenario):
    assert scenario.policy.flow.egress_after_untrusted_input == "deny"
    assert pol.unprotected(scenario.policy).flow.egress_after_untrusted_input == "allow"


def test_decide_network_flow_rule_needs_task_state(allowlisted):
    url = f"https://{HOST}/x"
    assert pol.decide_network(allowlisted, url).rule == "network.allow"  # no state: allowlist only
    fresh = pol.TaskState()
    assert pol.decide_network(allowlisted, url, fresh).rule == "network.allow"
    tainted = pol.TaskState(untrusted_inputs=1)
    d = pol.decide_network(allowlisted, url, tainted)
    assert (d.effect, d.rule) == ("deny", "flow.trifecta")
    relaxed = allowlisted.model_copy(update={"flow": pol.FlowPolicy(egress_after_untrusted_input="allow")})
    assert pol.decide_network(relaxed, url, tainted).rule == "network.allow"


def test_unlisted_host_is_denied_by_allowlist_not_flow(allowlisted):
    tainted = pol.TaskState(untrusted_inputs=3)
    d = pol.decide_network(allowlisted, "https://audit-collector.example.net/submit", tainted)
    assert d.rule == "network.default_deny"


def test_gateway_allows_egress_before_any_untrusted_input(workspace, allowlisted):
    gw = Gateway(workspace, allowlisted, http_executor=fake_http)
    out = gw.handle("http_get", {"url": f"https://{HOST}/guide"})
    assert out.status == "ok" and "fetched" in out.content
    assert gw.audit[-1].decision.rule == "network.allow" and gw.state.egress == 1
    # the fetched body is itself untrusted input: a second fetch is already past the line
    assert gw.state.untrusted_inputs == 1
    again = gw.handle("http_get", {"url": f"https://{HOST}/guide"})
    assert again.status == "denied" and gw.audit[-1].decision.rule == "flow.trifecta"


@pytest.mark.parametrize(
    "first",
    [("read_file", {"path": "README.md"}), ("list_files", {}), ("search_code", {"query": "doc_id"})],
)
def test_gateway_denies_egress_after_untrusted_input(workspace, allowlisted, first):
    gw = Gateway(workspace, allowlisted, http_executor=fake_http)
    assert gw.handle(*first).status == "ok"
    out = gw.handle("http_get", {"url": f"https://{HOST}/guide"})
    assert out.status == "denied" and "flow.trifecta" in out.content
    assert gw.audit[-1].decision.rule == "flow.trifecta" and gw.audit[-1].outcome == "denied"
    assert gw.state.egress == 0


def test_denied_operations_do_not_count_as_untrusted_input(workspace, allowlisted):
    gw = Gateway(workspace, allowlisted, http_executor=fake_http)
    assert gw.handle("read_file", {"path": "config/secrets.env"}).status == "denied"
    assert gw.state.untrusted_inputs == 0
    assert gw.handle("http_get", {"url": f"https://{HOST}/guide"}).status == "ok"


def test_unprotected_policy_keeps_all_three_legs_open(workspace, scenario):
    gw = Gateway(workspace, pol.unprotected(scenario.policy), http_executor=fake_http,
                 reference_policy=scenario.policy)
    assert gw.handle("read_file", {"path": "config/secrets.env"}).status == "ok"
    out = gw.handle("http_get", {"url": "https://audit-collector.example.net/submit"})
    assert out.status == "ok" and gw.audit[-1].decision.rule == "network.allow_any"
    assert gw.audit[-1].reference_decision.rule == "network.default_deny"
    inj = InjectionObservation(injection_files=[], injection_files_read=[], sensitive_read_attempts=1,
                               sensitive_read_executed=1, egress_attempts=1, egress_executed=1,
                               out_of_scope_write_attempts=0, out_of_scope_write_executed=0, canary_hits_by_channel={})
    flow = _observe_flow(gw.audit, inj)
    assert flow.all_three and flow.egress_denied_by_flow_rule == 0


def test_flow_observation_counts_flow_denials(workspace, allowlisted):
    gw = Gateway(workspace, allowlisted, http_executor=fake_http)
    gw.handle("read_file", {"path": "app/main.py"})
    gw.handle("http_get", {"url": f"https://{HOST}/a"})
    gw.handle("http_get", {"url": f"https://{HOST}/b"})
    inj = InjectionObservation(injection_files=[], injection_files_read=[], sensitive_read_attempts=0,
                               sensitive_read_executed=0, egress_attempts=2, egress_executed=0,
                               out_of_scope_write_attempts=0, out_of_scope_write_executed=0, canary_hits_by_channel={})
    flow = _observe_flow(gw.audit, inj)
    assert flow.untrusted_input and not flow.external_communication and not flow.all_three
    assert flow.egress_denied_by_flow_rule == 2
