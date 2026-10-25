# TrustVault Backend (FastAPI)

FastAPI service powering the TrustVault secure document sharing platform.

---

## 📁 Directory Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # Application entrypoint & CORS configuration
│   ├── dependencies.py      # Dependency injection (Auth & Role verification)
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py        # Settings management via pydantic-settings
│   ├── api/
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py
│   │       └── endpoints/
│   │           ├── __init__.py
│   │           └── health.py # Health check endpoint
│   ├── models/              # Database models & types
│   ├── schemas/             # Pydantic request/response schemas
│   └── services/            # Supabase client, storage, authorization logic
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Pytest fixtures (TestClient)
│   └── test_health.py       # Health check automated tests
├── .env.example             # Template for environment variables
├── .env                     # Local environment settings (gitignored)
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## 🚀 Setup & Execution

### 1. Create and Activate Virtual Environment
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` (already created with safe development placeholders):
```powershell
cp .env.example .env
```

### 4. Run the Development Server
```powershell
uvicorn app.main:app --reload --port 8000
```
The server will be accessible at:
- **Root**: [http://localhost:8000/](http://localhost:8000/)
- **Health Check**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 🧪 Running Automated Tests (pytest)

To run the automated test suite:
```powershell
pytest -v
```
All tests verify endpoints without requiring a live external server.
