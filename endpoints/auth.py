from fastapi import *
from basemodels.allpydmodels import *
from database import *
from utils.all_helper import *

router = APIRouter()

@router.post("/login")
async def login(user_data: UserLogin):
    user = users_collection.find_one({"username": user_data.username})
    if user and pwd_context.verify(user_data.password, user["password"]):
        access_token = create_access_token(
            data={"sub": user_data.username}
        )
        return {
            "status": "success",
            "username": user_data.username,
            "languages": user["languages"],
            "access_token": access_token,
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )

@router.post("/register")
async def register(user_data: UserRegister):
    existing_user = users_collection.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    access_token = create_access_token(
        data={"sub": user_data.username}
    )
    hashed_password = pwd_context.hash(user_data.password)
    users_collection.insert_one({
        "username": user_data.username,
        "password": hashed_password,
        "languages": {"SPANISH":0, "FRENCH":0, "GERMAN":0, "ITALIAN":0, "GUJARATI":0, "TELUGU":0, "JAPANESE":0},
    })
    return {
        "status": "success",
        "message": "Registration successful",
        "username": user_data.username,
        "languages": users_collection.find_one({"username": user_data.username})["languages"],
        "access_token": access_token,
    }

#logout endpoint
@router.post("/logout")
async def logout():
    return {
        "status": "success",
        "message": "Logout successful",
        "clear_data": True
    }
