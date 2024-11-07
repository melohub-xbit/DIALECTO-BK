from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from passlib.context import CryptContext
import dotenv
import os
from pydantic import BaseModel

app = FastAPI()

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
dotenv.load_dotenv()
uri = os.getenv('MONGO_URI')
client = MongoClient(uri, server_api=ServerApi('1'))
db = client["auth_db"]
users_collection = db["users"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(user_data: UserLogin):
    user = users_collection.find_one({"username": user_data.username})
    if user and pwd_context.verify(user_data.password, user["password"]):
        return {
            "status": "success",
            "username": user_data.username,
            "message": "Login successful"
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )

@app.post("/api/register")
async def register(user_data: UserRegister):
    existing_user = users_collection.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    hashed_password = pwd_context.hash(user_data.password)
    users_collection.insert_one({
        "username": user_data.username,
        "password": hashed_password
    })
    return {
        "status": "success",
        "message": "Registration successful"
    }

@app.get("/api/user/{username}")
async def get_user_profile(username: str):
    user = users_collection.find_one({"username": username}, {"password": 0})
    if user:
        return {
            "username": user["username"],
            "message": "Profile retrieved successfully"
        }
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found"
    )

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
