"""K8S-EXEC-001, K8S-SECRET-001 and K8S-WORKLOAD-002.

Every normalization here goes through _norm(), which also asserts the T-007.1
boundary: NormalizedEvent.raw must be {} for every event.
"""
import json
from pathlib import Path

import pytest
from k8s_helpers import gke, native, pod

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.engine.rule_loader import load_rule, load_rules
from cloudshield.engine.runner import run_event
from cloudshield.telemetry.kubernetes_audit import normalize_kubernetes_audit_event as normalize

RULES = Path(__file__).resolve().parent.parent / "rules"
EXEC, SECRET, HOST = "K8S-EXEC-001", "K8S-SECRET-001", "K8S-WORKLOAD-002"

FAKE_TOKEN = "FAKE-TOKEN-VALUE-do-not-use"
FAKE_KEY = "FAKE-PRIVATE-KEY-MATERIAL-do-not-use"
FAKE_PASSWORD = "not-a-real-password-123"
FAKE_B64 = "RkFLRS1TRUNSRVQtVkFMVUU="
SENTINELS = (FAKE_TOKEN, FAKE_KEY, FAKE_PASSWORD, FAKE_B64, "FAKE-STRINGDATA-VALUE")


def _norm(raw):
    event = normalize(raw)
    assert event.raw == {}
    return event


def _rule(name):
    return load_rule(str(RULES / "kubernetes" / name))


def _finding(rule_file, raw):
    return evaluate_rule(_rule(rule_file), _norm(raw))


def _exec(raw):
    return _finding("pod_exec.yaml", raw)


def _secret(raw):
    return _finding("secret_access.yaml", raw)


def _host(raw):
    return _finding("dangerous_host_workload.yaml", raw)


def _ctr(name="app", **security_context):
    return {"name": name, "securityContext": dict(security_context)}


def _host_pod(spec_extra=None, containers=None, init_containers=None):
    spec = {"containers": containers if containers is not None else [_ctr()]}
    if init_containers is not None:
        spec["initContainers"] = init_containers
    spec.update(spec_extra or {})
    return {"kind": "Pod", "metadata": {"name": "debug-shell", "namespace": "payments"}, "spec": spec}


def _everything(event, finding=None):
    return json.dumps({"attributes": event.attributes, "raw": event.raw, "resource": event.resource,
                       "principal": event.principal, "evidence": finding.evidence if finding else None}, default=str)


# ---- rule definitions ---------------------------------------------------------------------

def test_new_rules_are_plain_generic_yaml_with_documented_severity():
    exec_rule, secret_rule, host_rule = _rule("pod_exec.yaml"), _rule("secret_access.yaml"), _rule("dangerous_host_workload.yaml")

    assert (exec_rule.rule_id, exec_rule.severity, exec_rule.event_type) == (EXEC, "MEDIUM", "k8s.pod.exec")
    assert (secret_rule.rule_id, secret_rule.severity, secret_rule.event_type) == (SECRET, "HIGH", "k8s.secret.access")
    assert (host_rule.rule_id, host_rule.severity, host_rule.event_type) == (HOST, "HIGH", "k8s.workload.change")
    assert (exec_rule.mitre_attack, secret_rule.mitre_attack, host_rule.mitre_attack) == ("T1609", "T1552.007", "T1610")
    assert all(r.source == "kubernetes_audit" for r in (exec_rule, secret_rule, host_rule))
    assert len(load_rules(RULES)) == 8


# ---- K8S-EXEC-001 ---------------------------------------------------------------------------

def test_native_exec_fires_with_full_evidence():
    finding = _exec(native(verb="create", subresource="exec", code=101))

    assert finding.rule_id == EXEC and finding.severity == "MEDIUM"
    assert finding.principal == "developer@example.com"
    assert finding.resource == "namespaces/payments/pods/debug-shell"
    attributes = finding.evidence["event_attributes"]
    assert (attributes["is_exec"], attributes["verb"], attributes["subresource"]) == (True, "create", "exec")
    assert (attributes["namespace"], attributes["name"]) == ("payments", "debug-shell")
    assert attributes["source_ips"] == ["203.0.113.10"] and attributes["operation_succeeded"] is True
    assert finding.timestamp == "2024-08-06T09:00:01.000000Z"


def test_gke_exec_fires_and_matches_native_semantics():
    from_gke = _norm(gke("io.k8s.core.v1.pods.exec.create", "core/v1/namespaces/payments/pods/debug-shell/exec"))
    from_native = _norm(native(verb="create", subresource="exec", code=None))

    assert _exec(gke("io.k8s.core.v1.pods.exec.create", "core/v1/namespaces/payments/pods/debug-shell/exec")) is not None
    keys = ("verb", "api_group", "resource", "subresource", "namespace", "name", "is_exec", "source_ips")
    assert {k: from_gke.attributes[k] for k in keys} == {k: from_native.attributes[k] for k in keys}
    assert from_gke.event_type == from_native.event_type == "k8s.pod.exec"
    assert from_gke.attributes["format"] == "gke" and from_native.attributes["format"] == "native"


@pytest.mark.parametrize("verb", ["create", "get", "connect", "CREATE"])
def test_exec_is_not_tied_to_one_verb(verb):
    assert _exec(native(verb=verb, subresource="exec", code=101)) is not None


@pytest.mark.parametrize("method", [
    "io.k8s.core.v1.pods.exec.create", "IO.K8S.CORE.V1.PODS.EXEC.CREATE", "io.k8s.core.v1.pods.exec.get",
    "io.k8s.core.v1.Pods.Exec.Create",
])
def test_exec_method_matching_is_case_insensitive(method):
    assert _exec(gke(method, "core/v1/namespaces/payments/pods/debug-shell/exec")) is not None


def test_native_subresource_case_is_normalized():
    assert _exec(native(verb="create", subresource="Exec", code=101)) is not None


def test_failed_exec_does_not_alert_by_documented_decision():
    for code in (401, 403, 404, 500):
        assert _exec(native(verb="create", subresource="exec", code=code)) is None
    assert _exec(gke("io.k8s.core.v1.pods.exec.create", "core/v1/namespaces/payments/pods/x/exec",
                     status={"code": 7})) is None
    assert _norm(native(verb="create", subresource="exec", code=403)).attributes["operation_succeeded"] is False


def test_unknown_outcome_exec_alerts_and_missing_target_is_tolerated():
    assert _exec(native(verb="create", subresource="exec", code=None)) is not None
    finding = _exec(native(verb="create", subresource="exec", name=None, namespace=None, code=101))
    assert finding is not None and finding.resource == "pods"
    assert finding.evidence["event_attributes"]["name"] is None


@pytest.mark.parametrize("name,raw", [
    ("get pod", native(verb="get", code=200)),
    ("pods/log", native(verb="get", subresource="log", code=200)),
    ("pods/attach", native(verb="create", subresource="attach", code=101)),
    ("pods/portforward", native(verb="create", subresource="portforward", code=101)),
    ("pods/status", native(verb="update", subresource="status", code=200)),
    ("create pod", native(request=pod())),
    ("exec on non-core group", native(verb="create", subresource="exec", api_group="example.com", code=101)),
    ("exec on non-pod resource", native(verb="create", resource="services", subresource="exec", code=101)),
    ("exec with delete verb", native(verb="delete", subresource="exec", code=200)),
    ("exec verb list", native(verb="list", subresource="exec", code=200)),
    ("RequestReceived stage", native(verb="create", subresource="exec", stage="RequestReceived", code=None)),
    ("ResponseStarted stage", native(verb="create", subresource="exec", stage="ResponseStarted", code=101)),
    ("GKE malformed method (no verb)", gke("io.k8s.core.v1.pods.exec", "core/v1/namespaces/p/pods/x/exec")),
    ("GKE attach", gke("io.k8s.core.v1.pods.attach.create", "core/v1/namespaces/p/pods/x/attach")),
    ("GKE non-k8s method", gke("not.a.k8s.method", "x")),
    ("exec text only inside the request body",
     native(request={**pod(), "metadata": {"name": "x", "annotations": {"a": "pods/exec io.k8s.core.v1.pods.exec.create"}}})),
    ("objectRef malformed", native(verb="create", code=101, extra={"objectRef": "pods/x/exec"})),
    ("not kubernetes", {"protoPayload": {"methodName": "io.k8s.core.v1.pods.exec.create"}}),
])
def test_exec_negative_controls_do_not_fire(name, raw):
    assert _exec(raw) is None, name


def test_exec_finding_does_not_claim_malice():
    rule = _rule("pod_exec.yaml")

    assert "not inherently malicious" in rule.description
    assert "compromise" in rule.description  # only to disclaim it


# ---- K8S-SECRET-001 --------------------------------------------------------------------------

@pytest.mark.parametrize("verb,access_type", [("get", "read"), ("list", "enumeration"), ("watch", "watch")])
def test_secret_get_list_watch_fire_with_access_type(verb, access_type):
    name = "db-credentials" if verb == "get" else None
    finding = _secret(native(verb=verb, resource="secrets", name=name, code=200, level="Metadata"))

    assert finding.rule_id == SECRET and finding.severity == "HIGH"
    attributes = finding.evidence["event_attributes"]
    assert attributes["secret_access_type"] == access_type
    assert attributes["secret_name"] == name and attributes["namespace"] == "payments"
    assert attributes["verb"] == verb and attributes["source_ips"] == ["203.0.113.10"]
    assert finding.principal == "developer@example.com"
    assert finding.matched_values == {"attributes.secret_access_type": [access_type]}


def test_secret_native_gke_parity():
    from_native = _norm(native(verb="get", resource="secrets", name="db-credentials", code=200))
    from_gke = _norm(gke("io.k8s.core.v1.secrets.get", "core/v1/namespaces/payments/secrets/db-credentials"))
    keys = ("verb", "api_group", "resource", "namespace", "name", "secret_name", "secret_access_type")

    assert {k: from_native.attributes[k] for k in keys} == {k: from_gke.attributes[k] for k in keys}
    assert from_native.event_type == from_gke.event_type == "k8s.secret.access"
    assert _secret(gke("io.k8s.core.v1.secrets.list", "core/v1/namespaces/payments/secrets")) is not None
    assert _secret(gke("io.k8s.core.v1.secrets.watch", "core/v1/namespaces/payments/secrets")) is not None


@pytest.mark.parametrize("name,raw", [
    ("create secret", native(verb="create", resource="secrets", code=201)),
    ("update secret", native(verb="update", resource="secrets", code=200)),
    ("patch secret", native(verb="patch", resource="secrets", code=200)),
    ("delete secret", native(verb="delete", resource="secrets", code=200)),
    ("get configmap", native(verb="get", resource="configmaps", name="c", code=200)),
    ("list pods", native(verb="list", name=None, code=200)),
    ("non-core secrets", native(verb="get", resource="secrets", api_group="example.com", code=200)),
    ("secret subresource", native(verb="get", resource="secrets", subresource="status", code=200)),
    ("failed 403", native(verb="get", resource="secrets", code=403)),
    ("failed 404", native(verb="get", resource="secrets", code=404)),
    ("RequestReceived stage", native(verb="get", resource="secrets", stage="RequestReceived", code=None)),
    ("malformed objectRef", native(verb="get", code=200, extra={"objectRef": "secrets/x"})),
    ("GKE malformed method", gke("io.k8s.core.v1.secrets", "core/v1/namespaces/p/secrets/x")),
    ("GKE failed status", gke("io.k8s.core.v1.secrets.get", "core/v1/namespaces/p/secrets/x", status={"code": 7})),
    ("GKE create secret", gke("io.k8s.core.v1.secrets.create", "core/v1/namespaces/p/secrets/x")),
    ("empty object", {}),
])
def test_secret_negative_controls_do_not_fire(name, raw):
    assert _secret(raw) is None, name


def _secret_body(**extra):
    return {"kind": "Secret", "metadata": {"name": "db-credentials", "namespace": "payments"}, "type": "Opaque",
            "data": {"password": FAKE_B64, "apiKey": FAKE_TOKEN},
            "stringData": {"password": FAKE_PASSWORD, "privateKey": FAKE_KEY, "note": "FAKE-STRINGDATA-VALUE"},
            **extra}


SECRET_EVENTS = [
    ("native get with response data", native(verb="get", resource="secrets", name="db-credentials", code=200,
                                            level="RequestResponse", extra={"responseObject": _secret_body()})),
    ("native get with request body", native(verb="get", resource="secrets", name="db-credentials", code=200,
                                           request=_secret_body())),
    ("native list with response items", native(verb="list", resource="secrets", name=None, code=200,
                                              extra={"responseObject": {"kind": "SecretList", "items": [_secret_body()]}})),
    ("native watch", native(verb="watch", resource="secrets", name=None, code=200,
                            extra={"responseObject": _secret_body(), "annotations": {"leak": FAKE_TOKEN}})),
    ("native create (write, negative)", native(verb="create", resource="secrets", name="db", code=201,
                                              request=_secret_body(), extra={"responseObject": _secret_body()})),
    ("native update (write, negative)", native(verb="update", resource="secrets", name="db", code=200,
                                              request=_secret_body())),
    ("gke get with request", gke("io.k8s.core.v1.secrets.get", "core/v1/namespaces/payments/secrets/db-credentials",
                                 request=_secret_body())),
    ("gke create with data", gke("io.k8s.core.v1.secrets.create", "core/v1/namespaces/payments/secrets/db-credentials",
                                 request=_secret_body())),
    ("gke update with stringData", gke("io.k8s.core.v1.secrets.update",
                                       "core/v1/namespaces/payments/secrets/db-credentials",
                                       request={"stringData": {"k": "FAKE-STRINGDATA-VALUE"}, "data": {"k": FAKE_B64}})),
    ("gke status message", gke("io.k8s.core.v1.secrets.list", "core/v1/namespaces/payments/secrets",
                               status={"code": 0, "message": FAKE_TOKEN})),
]


@pytest.mark.parametrize("label,raw", SECRET_EVENTS, ids=[label for label, _ in SECRET_EVENTS])
def test_secret_material_never_reaches_attributes_raw_or_findings(label, raw):
    event = _norm(raw)
    finding = evaluate_rule(_rule("secret_access.yaml"), event)
    text = _everything(event, finding)

    for sentinel in SENTINELS:
        assert sentinel not in text, (label, sentinel)
    assert event.attributes["request_object"] is None


def test_secret_facts_are_an_allowlist_of_metadata():
    event = _norm(native(verb="get", resource="secrets", name="db-credentials", code=200, level="RequestResponse",
                         request=_secret_body(), extra={"responseObject": _secret_body()}))
    a = event.attributes

    assert (a["secret_access_type"], a["secret_name"], a["namespace"], a["verb"]) == ("read", "db-credentials", "payments", "get")
    assert "stringData" not in json.dumps(a) and "password" not in json.dumps(a)


def test_secret_rule_does_not_claim_theft():
    description = _rule("secret_access.yaml").description

    assert "does not mean a secret was stolen or exfiltrated" in description
    assert "audit policy" in description


# ---- K8S-WORKLOAD-002 ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag,attribute", [("hostNetwork", "host_network"), ("hostPID", "host_pid"),
                                            ("hostIPC", "host_ipc")])
def test_host_namespace_flags_fire(flag, attribute):
    finding = _host(native(request=_host_pod({flag: True})))

    assert finding.rule_id == HOST and finding.severity == "HIGH"
    attributes = finding.evidence["event_attributes"]
    assert attributes[attribute] is True and attributes["has_dangerous_host_config"] is True
    assert finding.principal == "developer@example.com" and finding.resource == "namespaces/payments/pods/debug-shell"


def test_host_path_volume_fires_and_keeps_only_safe_metadata():
    volume = {"name": "host-root", "hostPath": {"path": "/", "type": "Directory"}, "extra": "dropped"}
    body = _host_pod({"volumes": [volume, {"name": "scratch", "emptyDir": {}}]},
                     containers=[{**_ctr(), "volumeMounts": [{"name": "host-root", "mountPath": "/host"}]}])
    finding = _host(native(request=body))

    assert finding.evidence["event_attributes"]["host_path_volumes"] == [
        {"name": "host-root", "path": "/", "read_only": False}]
    assert "Directory" not in json.dumps(finding.evidence) and "dropped" not in json.dumps(finding.evidence)


@pytest.mark.parametrize("mounts,expected", [
    ([{"name": "v", "mountPath": "/a", "readOnly": True}], True),
    ([{"name": "v", "mountPath": "/a", "readOnly": True}, {"name": "v", "mountPath": "/b"}], False),
    ([{"name": "v", "mountPath": "/a", "readOnly": "true"}], False),
    ([], None),
])
def test_host_path_read_only_flag_comes_from_volume_mounts(mounts, expected):
    body = _host_pod({"volumes": [{"name": "v", "hostPath": {"path": "/var/log"}}]},
                     containers=[{**_ctr(), "volumeMounts": mounts}])
    finding = _host(native(request=body))

    assert finding.evidence["event_attributes"]["host_path_volumes"][0]["read_only"] is expected


@pytest.mark.parametrize("capability", ["SYS_ADMIN", "SYS_PTRACE"])
def test_dangerous_capabilities_fire(capability):
    finding = _host(native(request=_host_pod(containers=[_ctr("agent", capabilities={"add": [capability]})])))
    attributes = finding.evidence["event_attributes"]

    assert attributes["dangerous_capabilities"] == [capability]
    assert attributes["dangerous_capability_containers"] == ["agent"]


@pytest.mark.parametrize("value", ["sys_admin", "Sys_Admin", "CAP_SYS_ADMIN", "cap_sys_admin", " SYS_ADMIN "])
def test_capability_names_are_normalized(value):
    finding = _host(native(request=_host_pod(containers=[_ctr(capabilities={"add": [value]})])))

    assert finding.evidence["event_attributes"]["dangerous_capabilities"] == ["SYS_ADMIN"]


def test_init_and_ephemeral_containers_are_inspected():
    init = _host(native(request=_host_pod(init_containers=[_ctr("setup", capabilities={"add": ["SYS_ADMIN"]})])))
    ephemeral = _host(native(verb="update", code=200, request=_host_pod(
        {"ephemeralContainers": [_ctr("debugger", capabilities={"add": ["SYS_PTRACE"]})]})))

    assert init.evidence["event_attributes"]["dangerous_capability_containers"] == ["setup"]
    assert ephemeral.evidence["event_attributes"]["dangerous_capability_containers"] == ["debugger"]


def test_only_dangerous_capability_containers_are_named_and_others_ignored():
    body = _host_pod(containers=[_ctr("a", capabilities={"add": ["NET_BIND_SERVICE", "SYS_PTRACE"]}),
                                 _ctr("b", capabilities={"add": ["CHOWN"]}), _ctr("c")])
    attributes = _host(native(request=body)).evidence["event_attributes"]

    assert attributes["dangerous_capabilities"] == ["SYS_PTRACE"]
    assert attributes["dangerous_capability_containers"] == ["a"]


def test_gke_host_config_fires_and_matches_native():
    body = _host_pod({"hostPID": True})
    from_gke = _norm(gke(request=body))
    from_native = _norm(native(request=body))

    assert _host(gke(request=body)) is not None
    keys = ("has_dangerous_host_config", "host_pid", "host_network", "namespace", "name", "verb")
    assert {k: from_gke.attributes[k] for k in keys} == {k: from_native.attributes[k] for k in keys}


@pytest.mark.parametrize("name,raw", [
    ("benign pod", native(request=_host_pod())),
    ("flags false", native(request=_host_pod({"hostNetwork": False, "hostPID": False, "hostIPC": False}))),
    ("hostNetwork string", native(request=_host_pod({"hostNetwork": "true"}))),
    ("hostPID numeric 1", native(request=_host_pod({"hostPID": 1}))),
    ("hostIPC string", native(request=_host_pod({"hostIPC": "True"}))),
    ("unrelated capability", native(request=_host_pod(containers=[_ctr(capabilities={"add": ["NET_BIND_SERVICE"]})]))),
    ("dropped only", native(request=_host_pod(containers=[_ctr(capabilities={"drop": ["SYS_ADMIN"]})]))),
    ("capabilities not a list", native(request=_host_pod(containers=[_ctr(capabilities={"add": "SYS_ADMIN"})]))),
    ("capability non-strings", native(request=_host_pod(containers=[_ctr(capabilities={"add": [5, None, ["SYS_ADMIN"]]})]))),
    ("emptyDir volume only", native(request=_host_pod({"volumes": [{"name": "v", "emptyDir": {}}]}))),
    ("hostPath not an object", native(request=_host_pod({"volumes": [{"name": "v", "hostPath": "/"}]}))),
    ("volumes malformed", native(request=_host_pod({"volumes": "x"}))),
    ("deployment template", native(resource="deployments", api_group="apps", request={
        "spec": {"template": {"spec": {"hostNetwork": True}}}})),
    ("get pod", native(verb="get", code=200, request=_host_pod({"hostNetwork": True}))),
    ("delete pod", native(verb="delete", code=200, request=_host_pod({"hostNetwork": True}))),
    ("pods/status", native(verb="update", subresource="status", code=200, request=_host_pod({"hostNetwork": True}))),
    ("failed 403", native(code=403, request=_host_pod({"hostPID": True}))),
    ("RequestReceived stage", native(stage="RequestReceived", code=None, request=_host_pod({"hostPID": True}))),
    ("body unavailable", native()),
    ("json patch body", native(verb="patch", code=200, request=[{"op": "add", "path": "/spec/hostNetwork", "value": True}])),
    ("spec not an object", native(request={"spec": "x"})),
    ("GKE failed", gke(request=_host_pod({"hostPID": True}), status={"code": 7})),
    ("GKE malformed request", gke(request="text")),
])
def test_host_config_negative_controls_do_not_fire(name, raw):
    assert _host(raw) is None, name


def test_host_config_is_tri_state_and_unknown_is_not_false():
    unavailable = _norm(native()).attributes
    inspected = _norm(native(request=_host_pod())).attributes
    malformed = _norm(native(request={"spec": {"containers": "x"}})).attributes
    found_despite_malformed = _norm(native(request={"spec": {"hostPID": True, "containers": "x"}})).attributes

    assert unavailable["has_dangerous_host_config"] is None and unavailable["host_network"] is None
    assert inspected["has_dangerous_host_config"] is False and inspected["host_network"] is False
    assert malformed["has_dangerous_host_config"] is None
    assert found_despite_malformed["has_dangerous_host_config"] is True


def test_privileged_and_host_rules_are_independent_and_can_both_fire():
    rules = load_rules(RULES)
    both = _norm(native(request=_host_pod({"hostNetwork": True}, containers=[_ctr("agent", privileged=True)])))
    privileged_only = _norm(native(request=_host_pod(containers=[_ctr("agent", privileged=True)])))
    host_only = _norm(native(request=_host_pod({"hostNetwork": True})))

    assert sorted(f.rule_id for f in run_event(both, rules)) == ["K8S-WORKLOAD-001", HOST]
    assert [f.rule_id for f in run_event(privileged_only, rules)] == ["K8S-WORKLOAD-001"]
    assert [f.rule_id for f in run_event(host_only, rules)] == [HOST]


def test_host_rule_does_not_claim_container_escape():
    description = _rule("dangerous_host_workload.yaml").description

    assert "does not show that a container escape happened" in description


def test_workload_findings_carry_no_full_volume_or_spec_objects():
    body = _host_pod({"hostNetwork": True, "volumes": [{"name": "v", "hostPath": {"path": "/etc"},
                                                        "secret": {"secretName": FAKE_PASSWORD}}]})
    body["spec"]["containers"][0]["env"] = [{"name": "API_KEY", "value": FAKE_TOKEN}]
    event = _norm(native(request=body))
    finding = evaluate_rule(_rule("dangerous_host_workload.yaml"), event)
    text = _everything(event, finding)

    assert FAKE_TOKEN not in text and FAKE_PASSWORD not in text and "secretName" not in text
    assert finding.evidence["event_attributes"]["host_path_volumes"] == [{"name": "v", "path": "/etc", "read_only": None}]


# ---- cross-rule and boundary checks -----------------------------------------------------------

def test_existing_rules_still_fire_on_their_events():
    rules = load_rules(RULES)

    assert [f.rule_id for f in run_event(_norm(native(request=pod())), rules)] == ["K8S-WORKLOAD-001"]
    assert run_event(_norm(native(verb="create", subresource="exec", code=101)), rules)[0].rule_id == EXEC
    assert [f.rule_id for f in run_event(_norm(native(verb="get", resource="secrets", name="s", code=200)), rules)] == [SECRET]


def test_each_event_type_triggers_only_its_own_rules():
    rules = load_rules(RULES)
    cases = [
        (native(verb="create", subresource="exec", code=101), [EXEC]),
        (native(verb="list", resource="secrets", name=None, code=200), [SECRET]),
        (native(request=_host_pod({"hostIPC": True})), [HOST]),
        (native(verb="get", code=200), []),
    ]
    for raw, expected in cases:
        assert sorted(f.rule_id for f in run_event(_norm(raw), rules)) == sorted(expected)


def test_gcp_events_never_fire_kubernetes_rules_and_vice_versa():
    rules = load_rules(RULES)
    gcp_like = {"protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "SetIamPolicy"},
                "resource": {"type": "project"}}

    assert run_event(_norm(gcp_like), rules) == []


@pytest.mark.parametrize("raw", [
    native(verb="create", subresource="exec", code=101), native(verb="get", resource="secrets", code=200),
    native(request=_host_pod({"hostNetwork": True})), gke(request=_host_pod({"hostPID": True})),
    native(verb="get", resource="secrets", code=200, request=_secret_body(), extra={"responseObject": _secret_body()}),
    {}, "junk", None, native(extra={"objectRef": 5}),
])
def test_raw_is_always_empty_and_input_is_not_retained(raw):
    event = _norm(raw)

    assert event.raw == {} and event.raw is not raw
