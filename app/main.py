from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.db.mongodb import close_mongo, connect_to_mongo
from app.routers import auth
from app.routers import otp
from app.routers import virustotal

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    await connect_to_mongo()
    yield
    await close_mongo()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(auth.router)
app.include_router(otp.router)
app.include_router(virustotal.router)


@app.get("/", tags=["root"])
async def root():
    return {"message": "Hello World"}


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"app_name": settings.app_name},
    )


@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "ok"}
