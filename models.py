from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()


class DBUser(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_online = Column(Boolean, default=False)
    last_active = Column(DateTime, default=func.now())

    sent_messages = relationship(
        "DBMessage", foreign_keys="[DBMessage.sender_id]", back_populates="sender"
    )
    received_messages = relationship(
        "DBMessage", foreign_keys="[DBMessage.receiver_id]", back_populates="receiver"
    )

    def __repr__(self):
        return f"<DBUser(id='{self.id}', email='{self.email}', name='{self.name}', is_online={self.is_online})>"


class DBMessage(Base):
    __tablename__ = "messages"
    id = Column(String, primary_key=True, index=True)
    sender_id = Column(String, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(String, ForeignKey("users.id"), nullable=False)
    encrypted_content = Column(Text, nullable=False)
    encryption_key = Column(String, nullable=False)
    timestamp = Column(DateTime, default=func.now())

    sender = relationship(
        "DBUser", foreign_keys=[sender_id], back_populates="sent_messages"
    )
    receiver = relationship(
        "DBUser", foreign_keys=[receiver_id], back_populates="received_messages"
    )

    def __repr__(self):
        return f"<DBMessage(id='{self.id}', sender='{self.sender_id}', receiver='{self.receiver_id}', timestamp='{self.timestamp}')>"


class UserBase(BaseModel):
    email: EmailStr
    name: str


class UserCreate(UserBase):
    password: str


class UserInDB(UserBase):
    id: str
    hashed_password: str
    is_online: bool
    last_active: datetime

    class Config:
        from_attributes = True


class UserPublic(UserBase):
    id: str
    is_online: bool
    last_active: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    email: Optional[EmailStr] = None


class MessageCreate(BaseModel):
    receiver_id: str
    encrypted_content: str
    encryption_key: str


class MessageResponse(BaseModel):
    id: str
    sender_id: str
    receiver_id: str
    encrypted_content: str
    encryption_key: str
    timestamp: datetime

    class Config:
        from_attributes = True


# NUEVOS MODELOS para el cifrado/descifrado custom
class CustomEncryptRequest(BaseModel):
    message: str
    key: str


class CustomEncryptResponse(BaseModel):
    encrypted_message_base64: str


class CustomDecryptRequest(BaseModel):
    encrypted_message_base64: str
    key: str


class CustomDecryptResponse(BaseModel):
    decrypted_message: str
