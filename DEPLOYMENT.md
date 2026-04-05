# Deployment Guide

This guide covers deploying the Phishing Detection System, which consists of three parts: a FastAPI backend, a React frontend, and a Chrome Extension.

## 1. Environment Variables Configuration

Before deploying the backend, ensure your environment variables are properly configured.

```env
# Backend Environment Variables
API_KEY=your_super_secret_api_key
ALLOWED_ORIGINS=["https://your-frontend-domain.com", "chrome-extension://your-extension-id"]
RATE_LIMIT_PER_MINUTE=100
```

## 2. Deploying the Backend & Frontend (Combined)

The FastAPI app is configured to serve the built React frontend from the `frontend/dist` directory. This is the simplest deployment method.

### Step 2a: Build the Frontend
Navigate to the `frontend/` directory and build the production assets:
```bash
cd frontend
npm install
npm run build
cd ..
```

### Step 2b: Run via Docker (Recommended)

Create a `Dockerfile` in the root of your project:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend code
COPY app/ ./app/

# Copy the built frontend
COPY frontend/dist/ ./frontend/dist/

# Expose the port
EXPOSE 8000

# Run the FastAPI app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run the container:
```bash
docker build -t phishing-detection-system .
docker run -d -p 8000:8000 --env-file .env phishing-detection-system
```

## 3. Deploying Separately (PaaS - Vercel / Render)

If you prefer to separate the frontend and backend:

### Backend (e.g., Render, Railway, Fly.io)
1. Connect your GitHub repository to your PaaS of choice.
2. Set the build command: `pip install -r requirements.txt`
3. Set the start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Add your `.env` variables in the PaaS dashboard.
5. Once deployed, note your backend URL (e.g., `https://api.yourdomain.com`).

### Frontend (e.g., Vercel, Netlify)
1. Add a new project pointing to the `frontend/` directory.
2. Build command: `npm run build`
3. Output directory: `dist`
4. **Crucial:** Update your frontend API calls (e.g., in `useScan.js` and `axios` configurations) to point to your new backend URL instead of the local proxy. 

## 4. Deploying the Chrome Extension

Before distributing the Chrome extension to users or publishing it, you need to point it to your production backend.

### Step 4a: Update Extension Configuration
1. Open `extension/manifest.json`.
2. Update the `host_permissions` to match your production backend:
   ```json
   "host_permissions": [
     "https://api.yourdomain.com/*"
   ]
   ```
3. Open `extension/background.js`.
4. Update the `API_URL` constant:
   ```javascript
   const API_URL = "https://api.yourdomain.com/api/v1/scan";
   ```

### Step 4b: Package for Chrome Web Store
1. Open a terminal and navigate to the `extension/` directory.
2. Zip the contents of the extension directory (do not zip the folder itself, zip the contents):
   ```bash
   cd extension
   zip -r ../phishing-extension.zip *
   ```

### Step 4c: Publish
1. Go to the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole).
2. Click **New Item** and upload `phishing-extension.zip`.
3. Fill out the store listing details, upload icons, and provide a privacy policy.
4. Submit for review.

## Security Reminders for Production
- **Never** commit `.env` files to version control.
- Ensure your `ALLOWED_ORIGINS` in FastAPI is strictly set to your frontend domain and your specific Chrome Extension ID.
- Enable TLS/HTTPS for all backend endpoints.
