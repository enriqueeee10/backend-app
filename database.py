from sqlalchemy import create_engine, and_
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from typing import Generator, Optional, List
from datetime import datetime
from passlib.context import CryptContext
import secrets
import base64

from models import Base, DBUser, DBMessage

# --- Configuración de la Base de Datos PostgreSQL ---
DATABASE_URL = "postgresql://hertz:88aJ7UYnBfybSR0BeY2mvuKrr8vODiXP@dpg-d14q5iili9vc73erbtfg-a.oregon-postgres.render.com/cifrado"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_all_tables():
    """Crea todas las tablas definidas en los modelos de SQLAlchemy."""
    try:
        Base.metadata.create_all(bind=engine)
        print("Tablas de base de datos creadas/verificadas exitosamente.")
    except OperationalError as e:
        print(f"Error al conectar o crear tablas en la base de datos: {e}")
        print(
            "Asegúrate de que la URL de la base de datos sea correcta y que la base de datos esté accesible."
        )
    except Exception as e:
        print(f"Ocurrió un error inesperado al crear tablas: {e}")


def get_db() -> Generator[Session, None, None]:
    """Dependencia para obtener una sesión de base de datos."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Funciones CRUD para Usuarios (sin cambios) ---
def create_user(db: Session, email: str, name: str, password: str) -> DBUser:
    hashed_password = get_password_hash(password)
    user_id = secrets.token_urlsafe(16)
    db_user = DBUser(
        id=user_id,
        email=email,
        name=name,
        hashed_password=hashed_password,
        is_online=True,
        last_active=datetime.now(),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user_by_email(db: Session, email: str) -> Optional[DBUser]:
    return db.query(DBUser).filter(DBUser.email == email).first()


def get_user_by_id(db: Session, user_id: str) -> Optional[DBUser]:
    return db.query(DBUser).filter(DBUser.id == user_id).first()


def update_user_status(db: Session, user_id: str, is_online: bool):
    db_user = db.query(DBUser).filter(DBUser.id == user_id).first()
    if db_user:
        db_user.is_online = is_online
        db_user.last_active = datetime.now()
        db.commit()
        db.refresh(db_user)
        return True
    return False


def get_all_users(db: Session) -> List[DBUser]:
    return db.query(DBUser).all()


# --- Funciones CRUD para Mensajes ---
def add_message(
    db: Session,
    sender_id: str,
    receiver_id: str,
    encrypted_content: str,
    encryption_key: str,
) -> DBMessage:
    message_id = secrets.token_urlsafe(16)
    db_message = DBMessage(
        id=message_id,
        sender_id=sender_id,
        receiver_id=receiver_id,
        encrypted_content=encrypted_content,
        encryption_key=encryption_key,  # Esto ya viene cifrado de Flutter
        timestamp=datetime.now(),
    )
    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    return db_message


def get_messages_for_conversation(
    db: Session,
    user1_id: str,
    user2_id: str,
    after_timestamp: Optional[datetime] = None,
) -> List[DBMessage]:
    query = db.query(DBMessage).filter(
        ((DBMessage.sender_id == user1_id) & (DBMessage.receiver_id == user2_id))
        | ((DBMessage.sender_id == user2_id) & (DBMessage.receiver_id == user1_id))
    )

    if after_timestamp:
        query = query.filter(DBMessage.timestamp > after_timestamp)

    messages = query.order_by(DBMessage.timestamp).all()
    return messages
