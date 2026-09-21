import json
import sys
from collections import Counter
from pathlib import Path

import pytest
from k8s_helpers import RBAC, crb, gke, native, pod

from cloudshield.dataset import DatasetValidationError, find_sensitive_content, load_dataset
from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.engine.rule_loader import load_rule, load_rules
from cloudshield.engine.runner import run_event
from cloudshield.evaluation import evaluate_dataset
from cloudshield.telemetry.kubernetes_audit import normalize_kubernetes_audit_event as normalize
from cloudshield.telemetry.registry import get_adapter

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "kubernetes"
DATASET_DIR = ROOT / "datasets" / "kubernetes_audit"
GCP_DATASET_DIR = ROOT / "datasets" / "gcp_audit"
WL, RB = "K8S-WORKLOAD-001", "K8S-RBAC-001"
CRB = dict(resource="clusterrolebindings", namespace=None, name="dev-cluster-admin", api_group=RBAC)

sys.path.insert(0, str(ROOT / "scripts"))
import replay_dataset  # noqa: E402


def _wl(raw):
    return evaluate_rule(load_rule(str(RULES / "privileged_pod.yaml")), normalize(raw))


def _rb(raw):
    return evaluate_rule(load_rule(str(RULES / "rbac_cluster_admin_binding.yaml")), normalize(raw))


def _container(name="app", **security_context):
    return {"name": name, "securityContext": dict(security_context)}


# ---- rule definitions -----------------------------------------------------------------

def test_rules_are_loadable_and_reuse_the_generic_engine():
    wl = load_rule(str(RULES / "privileged_pod.yaml"))
    rb = load_rule(str(RULES / "rbac_cluster_admin_binding.yaml"))

    assert (wl.rule_id, wl.severity, wl.source, wl.event_type) == (WL, "HIGH", "kubernetes_audit", "k8s.workload.change")
    assert (rb.rule_id, rb.severity, rb.source, rb.event_type) == (RB, "HIGH", "kubernetes_audit", "k8s.rbac.binding_change")
    assert wl.mitre_attack == "T1610" and rb.mitre_attack == "T1098.006"


def test_five_rules_load_strictly_from_the_repository():
    assert {r.rule_id for r in load_rules(ROOT / "rules")} == {
        "GCP-IAM-001", "GCP-IAM-002", "GCP-IAM-003", RB, WL}


# ---- K8S-WORKLOAD-001 ---------------------------------------------------------------------

def test_privileged_regular_container_fires_with_full_evidence():
    finding = _wl(native(request=pod()))

    assert finding.rule_id == WL and finding.severity == "HIGH"
    assert finding.principal == "developer@example.com"
    assert finding.resource == "namespaces/payments/pods/debug-shell"
    assert finding.timestamp == "2024-08-06T09:00:01.000000Z"
    attributes = finding.evidence["event_attributes"]
    assert attributes["privileged_containers"] == ["debug-shell"]
    assert attributes["privileged_container_count"] == 1
    assert (attributes["verb"], attributes["namespace"], attributes["name"]) == ("create", "payments", "debug-shell")
    assert attributes["source_ips"] == ["203.0.113.10"]
    assert finding.matched_values == {"attributes.has_privileged_container": [True]}


def test_privileged_init_container_is_inspected():
    body = pod(containers=[_container(privileged=False)], init_containers=[_container("init-root", privileged=True)])
    finding = _wl(native(request=body))

    assert finding.evidence["event_attributes"]["privileged_containers"] == ["init-root"]


def test_only_the_privileged_container_of_several_is_named():
    body = pod(containers=[_container("web", allowPrivilegeEscalation=False), _container("agent", privileged=True),
                           _container("logs")], init_containers=[_container("setup", privileged=False)])
    attributes = _wl(native(request=body)).evidence["event_attributes"]

    assert attributes["privileged_containers"] == ["agent"] and attributes["privileged_container_count"] == 1


def test_multiple_privileged_containers_are_all_listed():
    body = pod(containers=[_container("a", privileged=True), _container("b", privileged=True)],
               init_containers=[_container("c", privileged=True)])

    assert _wl(native(request=body)).evidence["event_attributes"]["privileged_containers"] == ["a", "b", "c"]


def test_update_and_patch_verbs_fire_and_gke_unknown_outcome_fires():
    assert _wl(native(verb="update", code=200, request=pod())) is not None
    assert _wl(native(verb="patch", code=200, request={"spec": {"containers": [_container("x", privileged=True)]}})) is not None
    assert _wl(native(code=None, request=pod())) is not None
    assert _wl(gke(request=pod())) is not None


@pytest.mark.parametrize("name,raw", [
    ("privileged false", native(request=pod(containers=[_container(privileged=False)]))),
    ("no securityContext", native(request=pod(containers=[{"name": "app"}]))),
    ("allowPrivilegeEscalation only", native(request=pod(containers=[_container(allowPrivilegeEscalation=True)]))),
    ("privileged as string", native(request=pod(containers=[_container(privileged="true")]))),
    ("privileged as 1", native(request=pod(containers=[_container(privileged=1)]))),
    ("GET pod", native(verb="get", code=200, request=pod())),
    ("list pods", native(verb="list", name=None, code=200, request=pod())),
    ("delete pod", native(verb="delete", code=200, request=pod())),
    ("deployment template", native(resource="deployments", api_group="apps", request={
        "spec": {"template": {"spec": {"containers": [_container(privileged=True)]}}}})),
    ("configmap with privileged field", native(resource="configmaps", request={
        "spec": {"containers": [_container(privileged=True)]}})),
    ("non-core pods resource", native(resource="pods", api_group="example.com", request=pod())),
    ("pod status subresource", native(verb="update", subresource="status", code=200, request=pod())),
    ("body unavailable", native()),
    ("malformed containers", native(request={"spec": {"containers": "x", "initContainers": [None, 3]}})),
    ("malformed spec", native(request={"spec": "x"})),
    ("json patch list body", native(verb="patch", code=200, request=[{"op": "add", "path": "/spec", "value": 1}])),
    ("failed 403", native(code=403, request=pod())),
    ("failed 409", native(code=409, request=pod())),
    ("failed 500", native(code=500, request=pod())),
    ("RequestReceived stage", native(stage="RequestReceived", code=None, request=pod())),
    ("ResponseStarted stage", native(stage="ResponseStarted", code=None, request=pod())),
    ("GKE failed status", gke(request=pod(), status={"code": 7})),
    ("GKE get", gke(method="io.k8s.core.v1.pods.get", request=pod())),
    ("GKE malformed request", gke(request="text")),
])
def test_privileged_pod_negative_controls_do_not_fire(name, raw):
    assert _wl(raw) is None, name


def test_body_unavailable_is_unknown_not_false():
    attributes = normalize(native()).attributes
    inspected = normalize(native(request=pod(containers=[_container(privileged=False)]))).attributes

    assert attributes["has_privileged_container"] is None and attributes["privileged_container_count"] is None
    assert inspected["has_privileged_container"] is False and inspected["privileged_container_count"] == 0
    assert normalize(native(request={"spec": "x"})).attributes["has_privileged_container"] is None


def test_partially_malformed_containers_still_report_the_privileged_one():
    body = pod(containers=[None, _container("agent", privileged=True), "x"])

    assert _wl(native(request=body)).evidence["event_attributes"]["privileged_containers"] == ["agent"]


def test_unnamed_privileged_container_is_reported_by_position():
    body = pod(containers=[{"securityContext": {"privileged": True}}])

    assert _wl(native(request=body)).evidence["event_attributes"]["privileged_containers"] == ["containers[0]"]


# ---- K8S-RBAC-001 -----------------------------------------------------------------------------

def test_cluster_admin_binding_create_fires_with_full_evidence():
    finding = _rb(native(request=crb(), **CRB))

    assert finding.rule_id == RB and finding.severity == "HIGH"
    assert finding.principal == "developer@example.com"
    assert finding.resource == "clusterrolebindings/dev-cluster-admin"
    assert finding.timestamp == "2024-08-06T09:00:01.000000Z"
    attributes = finding.evidence["event_attributes"]
    assert (attributes["rbac_role_ref_kind"], attributes["rbac_role_ref_name"]) == ("ClusterRole", "cluster-admin")
    assert attributes["rbac_subjects"] == [{"kind": "User", "name": "developer@example.com"}]
    assert attributes["verb"] == "create" and attributes["source_ips"] == ["203.0.113.10"]
    assert finding.matched_values == {"attributes.rbac_role_ref_kind": ["ClusterRole"],
                                      "attributes.rbac_role_ref_name": ["cluster-admin"]}


@pytest.mark.parametrize("verb,code", [("create", 201), ("update", 200), ("patch", 200)])
def test_cluster_admin_binding_write_verbs_fire(verb, code):
    assert _rb(native(verb=verb, code=code, request=crb(), **CRB)) is not None


def test_gke_and_unknown_outcome_cluster_admin_bindings_fire():
    assert _rb(gke("io.k8s.authorization.rbac.v1.clusterrolebindings.create",
                   "rbac.authorization.k8s.io/v1/clusterrolebindings/dev-cluster-admin", request=crb())) is not None
    assert _rb(native(code=None, request=crb(), **CRB)) is not None


def test_subjects_keep_only_useful_string_fields_and_skip_malformed_entries():
    subjects = [{"kind": "ServiceAccount", "name": "deployer", "namespace": "ci", "extra": "dropped"},
                {"kind": "Group", "name": "ops@example.com", "apiGroup": RBAC}, "junk", None, {"name": 5}, {}]
    finding = _rb(native(request=crb(subjects=subjects), **CRB))

    assert finding.evidence["event_attributes"]["rbac_subjects"] == [
        {"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"},
        {"kind": "Group", "name": "ops@example.com", "apiGroup": RBAC}]


def test_missing_or_malformed_subjects_do_not_prevent_detection_or_crash():
    assert _rb(native(request=crb(subjects=None), **CRB)).evidence["event_attributes"]["rbac_subjects"] == []
    assert _rb(native(request=crb(subjects="x"), **CRB)).evidence["event_attributes"]["rbac_subjects"] == []


@pytest.mark.parametrize("name,raw", [
    ("view role", native(request=crb(role_name="view"), **CRB)),
    ("edit role", native(request=crb(role_name="edit"), **CRB)),
    ("GET clusterrolebinding", native(verb="get", code=200, request=crb(), **CRB)),
    ("delete clusterrolebinding", native(verb="delete", code=200, request=crb(), **CRB)),
    ("RoleBinding to cluster-admin", native(resource="rolebindings", namespace="payments", name="x",
                                            api_group=RBAC, request=crb())),
    ("Role kind named cluster-admin", native(request=crb(role_kind="Role"), **CRB)),
    ("name case near miss", native(request=crb(role_name="Cluster-Admin"), **CRB)),
    ("name with suffix", native(request=crb(role_name="cluster-admin-lite"), **CRB)),
    ("malformed roleRef string", native(request={"roleRef": "cluster-admin", "subjects": []}, **CRB)),
    ("roleRef missing name", native(request={"roleRef": {"kind": "ClusterRole"}}, **CRB)),
    ("roleRef non-string name", native(request={"roleRef": {"kind": "ClusterRole", "name": ["cluster-admin"]}}, **CRB)),
    ("missing body", native(**CRB)),
    ("body is a JSON patch list", native(verb="patch", code=200, request=[{"op": "add"}], **CRB)),
    ("clusterroles create", native(resource="clusterroles", namespace=None, name="cluster-admin", api_group=RBAC,
                                   request={"roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}})),
    ("wrong api group", native(request=crb(), **{**CRB, "api_group": "example.com"})),
    ("failed 403", native(code=403, request=crb(), **CRB)),
    ("failed 409", native(code=409, request=crb(), **CRB)),
    ("RequestReceived stage", native(stage="RequestReceived", code=None, request=crb(), **CRB)),
    ("GKE rolebindings", gke("io.k8s.authorization.rbac.v1.rolebindings.create",
                             "rbac.authorization.k8s.io/v1/namespaces/payments/rolebindings/x", request=crb())),
    ("GKE failed status", gke("io.k8s.authorization.rbac.v1.clusterrolebindings.create",
                              "rbac.authorization.k8s.io/v1/clusterrolebindings/x", request=crb(), status={"code": 7})),
])
def test_cluster_admin_binding_negative_controls_do_not_fire(name, raw):
    assert _rb(raw) is None, name


def test_privileged_pod_and_rbac_rules_never_fire_on_each_others_events():
    assert _rb(native(request=pod())) is None
    assert _wl(native(request=crb(), **CRB)) is None


def test_kubernetes_rules_ignore_gcp_events_and_gcp_rules_ignore_kubernetes_events():
    rules = load_rules(ROOT / "rules")
    gcp_like = {"protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "SetIamPolicy",
                                 "metadata": {"bindingDeltas": [{"action": "ADD", "role": "roles/owner"}]}}}

    assert run_event(normalize(gcp_like), rules) == []
    assert [f.rule_id for f in run_event(normalize(native(request=pod())), rules)] == [WL]
    assert [f.rule_id for f in run_event(normalize(native(request=crb(), **CRB)), rules)] == [RB]


# ---- cross-format parity --------------------------------------------------------------------------

def _semantics(event):
    a = event.attributes
    return (event.event_type, event.principal, event.resource, a["verb"], a["api_group"], a["resource"],
            a["namespace"], a["name"], a["source_ips"], a["has_privileged_container"],
            a["privileged_containers"], a["rbac_role_ref_kind"], a["rbac_role_ref_name"], a["rbac_subjects"])


def test_privileged_pod_native_and_gke_normalize_to_the_same_semantics():
    native_event = normalize(native(request=pod()))
    gke_event = normalize(gke(request=pod()))

    assert _semantics(native_event) == _semantics(gke_event)
    assert native_event.event_type == "k8s.workload.change"
    assert _wl(native(request=pod())) is not None and _wl(gke(request=pod())) is not None
    assert native_event.attributes["format"] == "native" and gke_event.attributes["format"] == "gke"


def test_cluster_admin_binding_native_and_gke_normalize_to_the_same_semantics():
    name = "rbac.authorization.k8s.io/v1/clusterrolebindings/dev-cluster-admin"
    native_event = normalize(native(request=crb(), **CRB))
    gke_event = normalize(gke("io.k8s.authorization.rbac.v1.clusterrolebindings.create", name, request=crb()))

    assert _semantics(native_event) == _semantics(gke_event)
    assert native_event.event_type == "k8s.rbac.binding_change"
    assert _rb(native(request=crb(), **CRB)) is not None
    assert _rb(gke("io.k8s.authorization.rbac.v1.clusterrolebindings.create", name, request=crb())) is not None


def test_native_and_gke_identities_remain_distinguishable():
    native_event, gke_event = normalize(native(request=pod())), normalize(gke(request=pod()))

    assert native_event.attributes["format"] != gke_event.attributes["format"]
    assert native_event.attributes["groups"] == ["system:authenticated"] and gke_event.attributes["groups"] == []
    assert native_event.attributes["cluster_name"] is None and gke_event.attributes["cluster_name"] == "lab-cluster"


# ---- corpus ---------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rules():
    return replay_dataset._bind_rules(load_rules(ROOT / "rules"))


@pytest.fixture(scope="module")
def dataset(rules):
    return load_dataset(DATASET_DIR, [r.rule_id for r in rules])


def _fired(event, rules):
    return sorted(f.rule_id for f in run_event(normalize(event.raw), rules))


def test_kubernetes_corpus_loads_and_declares_its_telemetry_type(dataset):
    assert dataset.telemetry_type == "kubernetes_audit"
    assert len(dataset.events) >= 30
    assert dataset.manifest["event_counts"]["total"] == len(dataset.events)
    assert {e.source_type for e in dataset.events} == {"synthetic_variant"}


def test_corpus_provenance_is_validated_and_documented(dataset):
    for event in dataset.events:
        assert event.derived_from and all(u.startswith("https://") for u in event.derived_from), event.event_id
        assert "not real telemetry" in event.source_reference
        assert not {"expected_rules", "event_id", "source_type", "derived_from"} & set(event.raw)
    formats = Counter(normalize(e.raw).attributes["format"] for e in dataset.events)
    assert formats["native"] >= 25 and formats["gke"] >= 6 and formats[None] >= 3


def test_corpus_has_the_requested_mix(dataset):
    def count(*tags):
        return sum(1 for e in dataset.events if set(tags) <= set(e.tags))

    assert count("workload", "true_positive") >= 6 and count("workload", "negative_control") >= 6
    assert count("rbac", "true_positive") >= 6 and count("rbac", "negative_control") >= 6
    assert count("generic") >= 6


def test_true_positives_fire_only_their_rule_and_everything_else_stays_silent(dataset, rules):
    for event in dataset.events:
        assert _fired(event, rules) == sorted(event.expected_rules), event.event_id


def test_corpus_metrics_are_exact_and_deterministic(dataset, rules):
    covered = dataset.manifest["rules_covered"]
    first = evaluate_dataset(dataset.events, rules, adapter=get_adapter("kubernetes_audit"), score_rules=covered)
    second = evaluate_dataset(dataset.events, rules, adapter=get_adapter("kubernetes_audit"), score_rules=covered)
    report = first.to_dict()

    assert report == second.to_dict()
    assert report["events"] == len(dataset.events)
    assert report["true_positives"] == report["actual_detections"] == 14
    assert (report["false_positives"], report["false_negatives"]) == (0, 0)
    assert report["true_negatives"] == len(dataset.events) * 2 - 14
    assert set(report["rules"]) == {WL, RB}
    assert report["rules"][WL]["true_positives"] == 7 and report["rules"][RB]["true_positives"] == 7
    assert report["mismatches"] == []


def test_kubernetes_replay_modes_agree(dataset, rules):
    sleeps = []
    adapter = get_adapter("kubernetes_audit")
    instant = evaluate_dataset(dataset.events, rules, adapter=adapter)
    accelerated = evaluate_dataset(dataset.events, rules, adapter=adapter, mode="accelerated", speed=1000,
                                   max_sleep_seconds=0.1, sleep=sleeps.append)

    assert accelerated == instant and sleeps and max(sleeps) <= 0.1


def test_dataset_files_contain_no_credential_material():
    files = [p for p in DATASET_DIR.rglob("*") if p.is_file()]

    assert {p.name for p in files} >= {"corpus.jsonl", "manifest.yaml", "sources.md", "README.md"}
    for path in files:
        assert find_sensitive_content(path.read_text(encoding="utf-8")) == [], path.name


@pytest.mark.parametrize("value", [
    "Bearer eyJhbGciOiJSUzI1NiJ9abcdefghij", "client-key-data: LS0tLS1CRUdJTi", "stringData", '"token": "abc"',
    "kubernetes.io/service-account-token", "ya29.abcdef", "-----BEGIN PRIVATE KEY-----",
    "someone@gmail.com", "10.1.2.3", "8.8.8.8",
])
def test_scanner_still_rejects_sensitive_material(value):
    assert find_sensitive_content(value)


@pytest.mark.parametrize("value", [
    "system:serviceaccount:payments:app", "system:node:gke-node-1", "kubernetes-admin", "system:anonymous",
    "developer@example.com", "prod@lab.iam.gserviceaccount.com", "203.0.113.10", "cluster-admin",
])
def test_kubernetes_usernames_and_fictional_identifiers_are_accepted(value):
    assert find_sensitive_content(value) == []


# ---- both dataset types dispatch correctly ----------------------------------------------------------------

def test_both_datasets_dispatch_to_their_own_normalizer(capsys):
    assert replay_dataset.main(["--dataset", str(GCP_DATASET_DIR)]) == 0
    gcp_out = capsys.readouterr().out
    assert replay_dataset.main(["--dataset", str(DATASET_DIR)]) == 0
    k8s_out = capsys.readouterr().out

    assert "telemetry_type=gcp_audit" in gcp_out and "events processed: 49" in gcp_out
    assert "GCP-IAM-003: TP=7 FP=0 FN=0" in gcp_out and "K8S-" not in gcp_out
    assert "telemetry_type=kubernetes_audit" in k8s_out and "GCP-IAM" not in k8s_out
    assert "K8S-WORKLOAD-001: TP=7" in k8s_out and "K8S-RBAC-001: TP=7" in k8s_out


def test_gcp_corpus_metrics_are_unchanged_by_generalization(rules):
    dataset = load_dataset(GCP_DATASET_DIR, [r.rule_id for r in rules])
    report = evaluate_dataset(dataset.events, rules, score_rules=dataset.manifest["rules_covered"]).to_dict()

    assert (report["events"], report["findings"]) == (49, 19)
    assert (report["true_positives"], report["false_positives"], report["false_negatives"]) == (19, 0, 0)
    assert report["true_negatives"] == 128


def test_unknown_or_missing_telemetry_type_is_rejected(tmp_path, rules):
    (tmp_path / "corpus.jsonl").write_text("", encoding="utf-8")
    for manifest in ("event_counts: {}\n", "telemetry_type: splunk\nevent_counts: {}\n"):
        (tmp_path / "manifest.yaml").write_text(manifest, encoding="utf-8")
        with pytest.raises(DatasetValidationError, match="telemetry_type"):
            load_dataset(tmp_path, [r.rule_id for r in rules])


def test_expected_rules_must_be_within_the_manifest_rules_covered(tmp_path, rules):
    envelope = {"event_id": "a", "source_type": "official_example", "source_reference": "ref",
                "expected_rules": ["GCP-IAM-001"], "raw": {"n": 1}}
    (tmp_path / "corpus.jsonl").write_text(json.dumps(envelope) + "\n", encoding="utf-8")
    (tmp_path / "manifest.yaml").write_text(
        "telemetry_type: kubernetes_audit\nrules_covered: [K8S-RBAC-001]\nevent_counts: {}\n", encoding="utf-8")

    with pytest.raises(DatasetValidationError, match="not in the manifest's rules_covered"):
        load_dataset(tmp_path, [r.rule_id for r in rules])


def test_synthetic_variant_needs_a_parent_or_documentation_urls(tmp_path, rules):
    def write(extra):
        envelope = {"event_id": "a", "source_type": "synthetic_variant", "source_reference": "ref",
                    "expected_rules": [], "raw": {"n": 1}, **extra}
        (tmp_path / "corpus.jsonl").write_text(json.dumps(envelope) + "\n", encoding="utf-8")
        (tmp_path / "manifest.yaml").write_text("telemetry_type: kubernetes_audit\nevent_counts: {}\n", encoding="utf-8")

    write({})
    with pytest.raises(DatasetValidationError, match="needs parent_event_id or derived_from"):
        load_dataset(tmp_path, [r.rule_id for r in rules])
    write({"derived_from": ["http://insecure.example.com/doc"]})
    with pytest.raises(DatasetValidationError, match="not an https URL"):
        load_dataset(tmp_path, [r.rule_id for r in rules])
    write({"derived_from": "https://kubernetes.io/docs/"})
    with pytest.raises(DatasetValidationError, match="derived_from must be a list"):
        load_dataset(tmp_path, [r.rule_id for r in rules])
