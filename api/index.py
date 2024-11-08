from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import dotenv
import os
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
import google.generativeai as genai
import json

app = FastAPI()

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
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

#gemini model
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
model = genai.GenerativeModel('gemini-pro')

# Security configurations
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserLogin(BaseModel):
    username: str
    password: str
    languages: dict

class UserRegister(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = users_collection.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

#determine level
def determine_user_level(points: int) -> str:
    if points < 100:
        return "beginner"
    elif points < 300:
        return "intermediate"
    else:
        return "advanced"

#generating flashcards
def generate_language_content_gemini(language: str, level: str) -> dict:
    prompt = f"""Generate 10 flashcards for {language} language learning at {level} level.
    Return only a JSON array with this exact structure:
    {{
        "cards": [
            {{
                "new_concept": "concept in {language}",
                "english": "english translation",
                "meaning": "detailed explanation",
                "example": "example sentence in {language}"
            }}
        ]
    }}"""
    
    response = model.generate_content(prompt)
    return json.loads(response.text)

@app.post("/login")
async def login(user_data: UserLogin):
    user = users_collection.find_one({"username": user_data.username})
    if user and pwd_context.verify(user_data.password, user["password"]):
        access_token = create_access_token(
            data={"sub": user_data.username}
        )
        return {
            "status": "success",
            "access_token": access_token,
            "token_type": "bearer",
            "username": user_data.username
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )

@app.post("/register")
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
        "password": hashed_password,
        "languages": {"SPANISH":0, "FRENCH":0, "GERMAN":0, "ITALIAN":0, "GUJARATI":0, "TELUGU":0, "JAPANESE":0},
    })
    return {
        "status": "success",
        "message": "Registration successful"
    }

@app.get("/user/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "rank": current_user["rank"],
        "points": current_user["points"],
        "message": "Profile retrieved successfully"
    }

# Health check endpoint
@app.get("/health")
async def health_check(current_user: dict = Depends(get_current_user)):
    return {"status": "healthy"}

@app.get("/home")
async def home(current_user: dict = Depends(get_current_user)):
    return {
        "current_user": {
            "username": current_user["username"],
            "languages": current_user["languages"]
        }
    }

@app.get("/home/leaderboard")
async def leaderboard(language: str = "SPANISH", current_user: dict = Depends(get_current_user)):
    # Find users who have points in the specified language
    pipeline = [
        {"$match": {f"languages.{language}": {"$exists": True}}},
        {"$project": {
            "_id": 0,
            "username": 1,
            "points": f"$languages.{language}"
        }},
        {"$sort": {"points": -1}},
        {"$addFields": {
            "rank": {"$add": [{"$indexOfArray": ["$points", "$points"]}, 1]}
        }}
    ]
    
    leaderboard_users = list(users_collection.aggregate(pipeline))
    
    return {
        "language": language,
        "leaderboard": leaderboard_users
    }


@app.get("/home/flashcards")
async def flashcards(language: str="SPANISH", current_user: dict = Depends(get_current_user)):
    user_points = current_user["languages"].get(language.upper(), 0)
    level = determine_user_level(user_points)
    flashcards_data = generate_language_content_gemini(language, level)
    
    return {
        "language": language,
        "level": level,
        "points": user_points,
        "flashcards": flashcards_data
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
