from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import SecureDocument, User
from app.schemas import DocumentCreate, DocumentResponse


router = APIRouter(
    prefix="/documents",
    tags=["Secure Documents"],
)


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_document(
    document_data: DocumentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    document = SecureDocument(
        owner_id=current_user.id,
        title=document_data.title,
        content=document_data.content,
    )

    db.add(document)
    db.commit()
    db.refresh(document)

    return document


@router.get(
    "",
    response_model=list[DocumentResponse],
)
def list_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    statement = (
        select(SecureDocument)
        .where(SecureDocument.owner_id == current_user.id)
        .order_by(SecureDocument.id.desc())
    )

    return db.scalars(statement).all()


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
)
def get_document(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    statement = select(SecureDocument).where(
        SecureDocument.id == document_id,
        SecureDocument.owner_id == current_user.id,
    )

    document = db.scalar(statement)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    return document