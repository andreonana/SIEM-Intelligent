# backend/app/db/database.py
#
# Moteur SQLAlchemy asynchrone partagé.
# Supporte PostgreSQL (asyncpg) et SQLite (aiosqlite) selon DATABASE_URL.
# Les tables sont créées automatiquement au démarrage si elles n'existent pas.

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# SQLite n'accepte pas check_same_thread en mode async — ignoré pour PG
_connect_args = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_async_engine(
    settings.database_url,
    echo=False,
    connect_args=_connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    """Crée toutes les tables si elles n'existent pas encore."""
    async with engine.begin() as conn:
        import app.models  # noqa: F401 — enregistre tous les modèles S1 + S2
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:  # type: ignore[return]
    """Dépendance FastAPI — session DB injectée dans chaque endpoint."""
    async with AsyncSessionLocal() as session:
        yield session
