"""Builders for Kubernetes audit test events (native Event and GKE wrapper)."""

RBAC = "rbac.authorization.k8s.io"


def pod(name="debug-shell", namespace="payments", containers="privileged", init_containers=None):
    if containers == "privileged":
        containers = [{"name": name, "securityContext": {"privileged": True}}]
    spec = {"containers": containers}
    if init_containers is not None:
        spec["initContainers"] = init_containers
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def crb(role_kind="ClusterRole", role_name="cluster-admin", subjects="default", name="dev-cluster-admin"):
    if subjects == "default":
        subjects = [{"kind": "User", "name": "developer@example.com"}]
    body = {"kind": "ClusterRoleBinding", "metadata": {"name": name},
            "roleRef": {"apiGroup": RBAC, "kind": role_kind, "name": role_name}}
    if subjects is not None:
        body["subjects"] = subjects
    return body


def native(verb="create", resource="pods", namespace="payments", name="debug-shell", api_group="", request=None,
           stage="ResponseComplete", code=201, user="developer@example.com", groups=("system:authenticated",),
           ips=("203.0.113.10",), subresource=None, extra=None, level="Request"):
    ref = {"resource": resource, "apiVersion": "v1"}
    for key, value in (("namespace", namespace), ("name", name), ("subresource", subresource)):
        if value is not None:
            ref[key] = value
    if api_group:
        ref["apiGroup"] = api_group
    event = {"apiVersion": "audit.k8s.io/v1", "kind": "Event", "level": level, "auditID": "00000000-0000-4000-8000-000000000001",
             "stage": stage, "verb": verb, "user": {"username": user, "groups": list(groups)},
             "sourceIPs": list(ips), "userAgent": "kubectl/v1.30.0", "objectRef": ref,
             "requestReceivedTimestamp": "2024-08-06T09:00:00.000000Z", "stageTimestamp": "2024-08-06T09:00:01.000000Z"}
    if code is not None:
        event["responseStatus"] = {"code": code}
    if request is not None:
        event["requestObject"] = request
    event.update(extra or {})
    return event


def gke(method="io.k8s.core.v1.pods.create", resource_name="core/v1/namespaces/payments/pods/debug-shell",
        request=None, principal="developer@example.com", ip="203.0.113.10", status=None, labels=None):
    payload = {"serviceName": "k8s.io", "methodName": method, "resourceName": resource_name,
               "authenticationInfo": {"principalEmail": principal},
               "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": "kubectl/v1.30.0"}}
    if request is not None:
        payload["request"] = request
    if status is not None:
        payload["status"] = status
    return {"logName": "projects/cloudshield-lab/logs/cloudaudit.googleapis.com%2Factivity",
            "resource": {"type": "k8s_cluster", "labels": labels or {
                "project_id": "cloudshield-lab", "cluster_name": "lab-cluster", "location": "us-central1"}},
            "protoPayload": payload, "timestamp": "2024-08-06T09:00:01.000000Z"}
