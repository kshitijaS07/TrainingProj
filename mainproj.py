from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy import create_engine, String, Float, Integer, ForeignKey, select, text, inspect
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
    Session
)

import jwt
import bcrypt
import json

from datetime import datetime, timedelta, timezone

# =========================
# JWT CONFIG
# =========================

SECRET_KEY = "expense_tracker_secret_key_12345678901234567890"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# =========================
# DATABASE
# =========================

engine = create_engine(
    "sqlite:///expense_tracker.db",
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


class Base(DeclarativeBase):
    pass


# =========================
# USER TABLE
# =========================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(String(50))

    email: Mapped[str] = mapped_column(
        String(100),
        unique=True
    )

    hashed_password: Mapped[str] = mapped_column(
        String(200)
    )


# =========================
# EXPENSE TABLE
# =========================

class Expense(Base):
    __tablename__ = "expenses"

    id: Mapped[int] = mapped_column(primary_key=True)

    title: Mapped[str] = mapped_column(
        String(100)
    )

    category: Mapped[str] = mapped_column(
        String(50)
    )

    amount: Mapped[float] = mapped_column(
        Float
    )

    expense_type: Mapped[str] = mapped_column(
        String(20)
    )

    note: Mapped[str] = mapped_column(
        String(300)
    )

    date: Mapped[str] = mapped_column(
        String(30)
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id")
    )


Base.metadata.create_all(bind=engine)

# Ensure the expenses table has the user_id column for older databases
with engine.connect() as conn:
    inspector = inspect(engine)
    columns = [c['name'] for c in inspector.get_columns('expenses')]
    if 'user_id' not in columns:
        conn.execute(text('ALTER TABLE expenses ADD COLUMN user_id INTEGER'))
        conn.commit()

# =========================
# APP
# =========================

app = FastAPI()

templates = Jinja2Templates(
    directory="Frontend"
)

@app.get("/test")
def test():
    return {
        "message": "FastAPI Working"
    }
# =========================
# DATABASE DEPENDENCY
# =========================


def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# =========================
# PASSWORD FUNCTIONS
# =========================

def get_password_hash(password):

    return bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()


def verify_password(
        plain_password,
        hashed_password
):

    return bcrypt.checkpw(
        plain_password.encode(),
        hashed_password.encode()
    )


# =========================
# JWT TOKEN
# =========================

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


# =========================
# CURRENT USER
# =========================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    print("TOKEN =", request.cookies.get("access_token"))
    token = request.cookies.get(
        "access_token"
    )

    if not token:
        return None

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        email = payload.get("sub")

        if email is None:
            return None

    except:

        return None

    user = db.scalars(
        select(User).where(
            User.email == email
        )
    ).first()

    return user


# =========================
# SIGNUP
# =========================

@app.get(
    "/signup",
    response_class=HTMLResponse
)
def signup_page(
    request: Request
):

    return templates.TemplateResponse(
        request=request,
        name="signup.html"
    )


@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    existing_user = db.scalars(
        select(User).where(
            User.email == email
        )
    ).first()

    if existing_user:

        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "error":
                "Email already exists"
            }
        )

    user = User(
        name=name,
        email=email,
        hashed_password=
        get_password_hash(password)
    )

    db.add(user)
    db.commit()

    return RedirectResponse(
        url="/login",
        status_code=303
    )


# =========================
# LOGIN
# =========================

@app.get(
    "/login",
    response_class=HTMLResponse
)
def login_page(
    request: Request
):

    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )


@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = db.scalars(
        select(User).where(
            User.email == email
        )
    ).first()

    if (
        not user
        or
        not verify_password(
            password,
            user.hashed_password
        )
    ):

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error":
                "Invalid Email or Password"
            }
        )

    token = create_access_token(
        {
            "sub": user.email
        }
    )

    response = RedirectResponse(
        url="/",
        status_code=303
    )

    response.set_cookie(
    key="access_token",
    value=token,
    httponly=True,
    samesite="lax"
    )

    return response


# =========================
# LOGOUT
# =========================

@app.get("/logout")
def logout():

    response = RedirectResponse(
        url="/login",
        status_code=303
    )

    response.delete_cookie(
        "access_token"
    )

    return response


# =========================
# DASHBOARD
# =========================

@app.get("/", response_class=HTMLResponse)
def home_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expenses = db.scalars(
    select(Expense).where(
        Expense.user_id == current_user.id
    )
).all()

    income = sum(
        e.amount
        for e in expenses
        if e.expense_type == "Income"
    )

    expense = sum(
        e.amount
        for e in expenses
        if e.expense_type == "Expense"
    )

    balance = income - expense
    total = income + expense
    income_ratio = int((income / total) * 100) if total else 0
    expense_ratio = int((expense / total) * 100) if total else 0

    # Monthly breakdown for chart
    months = [
        "Jan", "Feb", "Mar", "Apr",
        "May", "Jun", "Jul", "Aug",
        "Sep", "Oct", "Nov", "Dec"
    ]

    monthly_income = [0] * 12
    monthly_expense = [0] * 12

    for e in expenses:
        try:
            month_index = datetime.fromisoformat(e.date).month - 1
        except Exception:
            month_index = None

        if month_index is not None and 0 <= month_index < 12:
            if e.expense_type == "Income":
                monthly_income[month_index] += e.amount
            elif e.expense_type == "Expense":
                monthly_expense[month_index] += e.amount

    chart_data = {
        "months": months,
        "income": monthly_income,
        "expense": monthly_expense
    }

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "current_user": current_user,
            "expenses": expenses,
            "income": income,
            "expense": expense,
            "balance": balance,
            "income_ratio": income_ratio,
            "expense_ratio": expense_ratio,
            "chart_data": chart_data
        }
    )


# =========================
# CREATE PAGE
# =========================

@app.get(
    "/create",
    response_class=HTMLResponse
)
def create_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):

    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="create.html",
        context={
            "current_user": current_user
        }
    )


# =========================
# CREATE EXPENSE
# =========================

@app.post("/create")
def create_expense(
    title: str = Form(...),
    category: str = Form(...),
    amount: float = Form(...),
    expense_type: str = Form(...),
    note: str = Form(""),
    date: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    try:
        expense = Expense(
            title=title,
            category=category,
            amount=amount,
            expense_type=expense_type,
            note=note,
            date=date,
            user_id=current_user.id
        )

        db.add(expense)
        db.commit()
        db.refresh(expense)

        print(f"Expense Saved: {title} - ₹{amount}")

    except Exception as e:
        db.rollback()
        print("DATABASE ERROR:", e)

    return RedirectResponse(
        url="/",
        status_code=303
    )


# =========================
# UPDATE PAGE
# =========================

@app.get(
    "/update/{expense_id}",
    response_class=HTMLResponse
)
def update_page(
    request: Request,
    expense_id: int,
    db: Session = Depends(get_db),
    current_user:
    User = Depends(get_current_user)
):

    if not current_user:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )

    return templates.TemplateResponse(
        request=request,
        name="update.html",
        context={
            "expense": expense
        }
    )


# =========================
# UPDATE EXPENSE
# =========================

@app.post("/update/{expense_id}")
def update_expense(
    expense_id: int,
    title: str = Form(...),
    category: str = Form(...),
    amount: float = Form(...),
    expense_type: str = Form(...),
    note: str = Form(""),
    date: str = Form(...),
    db: Session = Depends(get_db),
    current_user:
    User = Depends(get_current_user)
):

    expense = db.get(
        Expense,
        expense_id
    )

    if expense:

        expense.title = title
        expense.category = category
        expense.amount = amount
        expense.expense_type = expense_type
        expense.note = note
        expense.date = date

        db.commit()

    return RedirectResponse(
        url="/",
        status_code=303
    )


# =========================
# DELETE EXPENSE
# =========================

@app.get("/delete/{expense_id}")
def delete_expense(
    expense_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )

    if expense and expense.user_id == current_user.id:
        db.delete(expense)
        db.commit()

    return RedirectResponse(
        url="/",
        status_code=303
    )