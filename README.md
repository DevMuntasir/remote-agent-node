# Remote Share - Split Backend + React Frontend

This repository now contains two separate apps:

- Backend API/socket server at project root (`index.js`)
- React frontend dashboard at `frontend/`

## Run backend

```bash
npm install
npm run dev:api
```

## Run frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Set `VITE_API_BASE_URL` in `frontend/.env` to your backend URL.

## Useful scripts (from root)

- `npm run dev:api` - run backend with nodemon
- `npm run dev:ui` - run React frontend
- `npm run build:ui` - build frontend bundle
- `npm run preview:ui` - preview frontend build
# remote-agent-ui-react
