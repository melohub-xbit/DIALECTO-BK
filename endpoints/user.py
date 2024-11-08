from fastapi import *
from basemodels.allpydmodels import *
from utils.all_helper import *
from database import *

router = APIRouter()

@router.get("/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "rank": current_user["rank"],
        "points": current_user["points"],
        "message": "Profile retrieved successfully"
    }

# Health check endpoint
@router.get("/health")
async def health_check():
    return {"status": "healthy"}

@router.get("/home")
async def home(current_user: dict = Depends(get_current_user)):
    return {
        "current_user": {
            "username": current_user["username"],
            "languages": current_user["languages"]
        }
    }