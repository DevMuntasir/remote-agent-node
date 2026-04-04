# Agent Release Hosting (signal-server)

This server can host `RemoteAgent.exe` and `latest.json` for auto-update.

## Public URLs

- Binary: `https://<your-domain>/agent/RemoteAgent.exe`
- Manifest: `https://<your-domain>/agent/latest.json`

Set agent `.env` value:

- `UPDATE_MANIFEST_URL=https://<your-domain>/agent/latest.json`

## Publish a new release (upload EXE + manifest)

Use an admin Firebase ID token as Bearer token.

```bash
curl -X PUT "https://<your-domain>/admin/agent/release/upload?version=2026.04.04.223733" \
  -H "Authorization: Bearer <ADMIN_ID_TOKEN>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @dist/RemoteAgent.exe
```

This writes:

- `agent-updates/RemoteAgent.exe`
- `agent-updates/latest.json`

## Publish from Admin UI

- Login to dashboard as admin.
- Go to **Agent Release** panel.
- Enter version, choose `RemoteAgent.exe`, click **Publish Release**.
- Or click **Publish + Update All** to publish and broadcast update check to all online devices.

## Update manifest only (external binary host)

```bash
curl -X POST "https://<your-domain>/admin/agent/release/manifest" \
  -H "Authorization: Bearer <ADMIN_ID_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"version":"2026.04.04.223733","url":"https://cdn.example.com/RemoteAgent.exe","sha256":"<sha256>"}'
```

## Important note for Render

If your Render service does not use a persistent disk, uploaded files are ephemeral and can be lost on restart/redeploy.
In that case, host `RemoteAgent.exe` on durable storage (S3/R2/GitHub Releases/Cloudinary raw) and use the manifest-only endpoint.
