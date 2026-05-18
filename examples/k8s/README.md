# Kubernetes Examples

Files in this folder are ready-to-adapt templates for `passwork-cli`.

Replace placeholder values such as `<item-id>`, image names, namespace names, and secret values before applying these manifests.

## Files

- `deployment-wrapper-default.yaml`  
  Runtime env injection for default encryption mode.

- `deployment-wrapper-cse.yaml`  
  Runtime env injection for client-side encryption mode.

- `deployment-initcontainer-file.yaml`  
  InitContainer fetches secret and writes file to memory volume.

- `create-secrets.sh`  
  Helper script to create Kubernetes secrets with required env vars.

## Usage

1. Create Kubernetes secrets:

```bash
bash examples/k8s/create-secrets.sh
```

2. Apply one of deployments:

```bash
kubectl apply -f examples/k8s/deployment-wrapper-default.yaml
```

3. Check pod logs/status:

```bash
kubectl get pods -n default
kubectl logs deploy/myapp-default -n default
```
