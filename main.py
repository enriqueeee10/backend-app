from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import secrets
from sqlalchemy.orm import Session

from models import (
    UserCreate,
    UserPublic,
    Token,
    TokenData,
    MessageCreate,
    MessageResponse,
    DBUser,
    CustomEncryptRequest,
    CustomEncryptResponse,
    CustomDecryptRequest,
    CustomDecryptResponse,  # NUEVOS MODELOS
)
from database import (
    get_password_hash,
    verify_password,
    create_user,
    get_user_by_email,
    get_user_by_id,
    update_user_status,
    get_all_users,
    add_message,
    get_messages_for_conversation,
    get_db,
    create_all_tables,
)
from encryption_utils import (
    custom_encrypt,
    custom_decrypt,
)  # NUEVO: Importar funciones de cifrado custom

# --- Configuración de FastAPI ---
app = FastAPI(
    title="Crypto Chat Backend",
    description="API para gestionar usuarios, su estado y mensajes de chat encriptados.",
    version="0.0.1",
    on_startup=[create_all_tables],
)

# --- Configuración de JWT (JSON Web Token) ---
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> DBUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, token_data.email)
    if user is None:
        raise credentials_exception
    return user


# --- Endpoints de Autenticación ---


@app.post("/register", response_model=UserPublic, summary="Registrar un nuevo usuario")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El email ya está registrado",
        )
    new_user = create_user(db, user.email, user.name, user.password)
    return UserPublic.from_orm(new_user)


@app.post("/token", response_model=Token, summary="Obtener token de acceso para login")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    update_user_status(db, user.id, True)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get(
    "/users/me",
    response_model=UserPublic,
    summary="Obtener información del usuario actual",
)
async def read_users_me(current_user: DBUser = Depends(get_current_user)):
    return UserPublic.from_orm(current_user)


@app.post("/logout", summary="Cerrar sesión del usuario")
async def logout_user(
    current_user: DBUser = Depends(get_current_user), db: Session = Depends(get_db)
):
    update_user_status(db, current_user.id, False)
    return {"message": "Sesión cerrada correctamente"}


# --- Endpoints de Usuarios ---


@app.get(
    "/users",
    response_model=List[UserPublic],
    summary="Obtener lista de todos los usuarios (excepto el actual)",
)
async def get_users(
    current_user: DBUser = Depends(get_current_user), db: Session = Depends(get_db)
):
    all_users = get_all_users(db)
    return [
        UserPublic.from_orm(user) for user in all_users if user.id != current_user.id
    ]


# --- Endpoints de Chat ---


@app.post(
    "/messages", response_model=MessageResponse, summary="Enviar un mensaje cifrado"
)
async def send_message(
    message: MessageCreate,
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    receiver = get_user_by_id(db, message.receiver_id)
    if not receiver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El usuario receptor no existe",
        )

    db_message = add_message(
        db,
        sender_id=current_user.id,
        receiver_id=message.receiver_id,
        encrypted_content=message.encrypted_content,
        encryption_key=message.encryption_key,
    )
    return MessageResponse.from_orm(db_message)


@app.get(
    "/messages/{other_user_id}",
    response_model=List[MessageResponse],
    summary="Obtener mensajes de una conversación",
)
async def get_conversation_messages(
    other_user_id: str,
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db),
    after_timestamp: Optional[datetime] = Query(
        None,
        description="Obtener mensajes enviados después de este timestamp (ISO 8601)",
    ),
):
    other_user = get_user_by_id(db, other_user_id)
    if not other_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El usuario de la conversación no existe",
        )

    messages = get_messages_for_conversation(
        db, current_user.id, other_user_id, after_timestamp=after_timestamp
    )
    return [MessageResponse.from_orm(msg) for msg in messages]


# --- NUEVOS Endpoints de Cifrado/Descifrado Custom ---


@app.post(
    "/encrypt_custom",
    response_model=CustomEncryptResponse,
    summary="Cifrar un mensaje con la lógica custom",
)
async def encrypt_message_custom(request: CustomEncryptRequest):
    try:
        encrypted_text_base64 = custom_encrypt(request.message, request.key)
        return CustomEncryptResponse(encrypted_message_base64=encrypted_text_base64)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno al cifrar: {e}",
        )


@app.post(
    "/decrypt_custom",
    response_model=CustomDecryptResponse,
    summary="Descifrar un mensaje con la lógica custom",
)
async def decrypt_message_custom(request: CustomDecryptRequest):
    try:
        decrypted_text = custom_decrypt(request.encrypted_message_base64, request.key)
        return CustomDecryptResponse(decrypted_message=decrypted_text)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno al descifrar: {e}",
        )
