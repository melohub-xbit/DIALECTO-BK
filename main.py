from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import dotenv
import os
from fastapi.security import OAuth2PasswordBearer
import google.generativeai as genai
import json
from basemodels.allpydmodels import *
from utils.all_helper import *
from utils.story_helper import *
from endpoints import auth, games, games_word
from database import *

app = FastAPI()

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#routers
app.include_router(auth.router, tags=["Auth"])
app.include_router(games.router, tags=["Games"])
app.include_router(games_word.router, tags=["Games"])

@app.middleware("http")
async def add_cors_header(request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
    return response

#logout endpoint
@app.post("/logout")
async def logout():
    return {
        "status": "success",
        "message": "Logout successful",
        "clear_data": True
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
