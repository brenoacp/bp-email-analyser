import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.core.logging import log_http_access, setup_audit_logging

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Forense de Cabeçalho de E-mail e Detecção de Fraude",
    version="1.0.0",
)

# Initialize audit logging handlers
setup_audit_logging()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def audit_http_middleware(request: Request, call_next):
    start_time = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        log_http_access(
            client_ip=client_ip,
            user_agent=user_agent,
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            latency_ms=duration_ms,
        )


app.include_router(router, prefix=settings.API_PREFIX)
