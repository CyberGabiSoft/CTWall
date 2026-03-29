### Password reset

To reset the admin credentials use script:
```bash
./manual-test-scripts/reset_admin_credentials.sh
```
The script:

1. ensures PostgreSQL is running and healthy,
2. verifies `admin@ctwall` exists in DB,
3. generates a new Argon2id password hash locally,
4. updates admin password hash directly in PostgreSQL,
5. writes fresh `/app/data/bootstrap-admin-credentials.json`,
6. prints fresh admin credentials and raw credentials JSON.

No initializer container is run by this script, so it does not trigger migrations.

Reset Helm/Kubernetes admin credentials (without wiping DB):
```bash
NAMESPACE="${NS:-ctwall}" HELM_RELEASE=ctwall ./manual-test-scripts/reset_admin_credentials_k8s.sh
```

