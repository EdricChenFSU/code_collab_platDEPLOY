# Self-hosting with Coolify

This project can run on a small always-on Linux VM with Docker. The recommended free-ish setup is an Oracle Cloud Always Free Ubuntu VM with Coolify installed.

## App settings

Coolify should deploy this repository using the included `Dockerfile`.

Use these environment variables:

```env
PORT=3000
DATA_DIR=/data
SECRET_KEY=replace-with-a-long-random-secret
```

Attach persistent storage:

```text
Container path: /data
```

The app stores runtime data in `/data`:

- `/data/users.db`
- `/data/accounts/`

## Coolify setup

1. Create or open a Coolify server.
2. Add a new resource.
3. Choose GitHub repository deployment.
4. Select this repository.
5. Choose Dockerfile build.
6. Set the port to `3000`.
7. Add the environment variables above.
8. Add persistent storage mounted to `/data`.
9. Deploy.

## Updating

After Coolify is connected to GitHub, pushes to the selected branch can redeploy the app automatically.

## Local Docker test

```bash
docker build -t collaborative-code-platform .
docker run --rm -p 3000:3000 \
  -e SECRET_KEY=local-dev-secret \
  -e DATA_DIR=/data \
  -v collaborative-code-data:/data \
  collaborative-code-platform
```

Then open:

```text
http://localhost:3000
```
