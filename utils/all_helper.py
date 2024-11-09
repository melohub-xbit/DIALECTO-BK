from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import dotenv
import os
from fastapi.security import OAuth2PasswordBearer
import google.generativeai as genai
import json
from pymongo import MongoClient
from pymongo.server_api import ServerApi

# Database setup
dotenv.load_dotenv()
uri = os.getenv('MONGO_URI')
client = MongoClient(uri, server_api=ServerApi('1'))
storydb = client["story_db"]

#gemini model
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
model = genai.GenerativeModel('gemini-pro')

# Security configurations
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#determine level
def determine_user_level(points: int) -> str:
    if points < 100:
        return "beginner"
    elif points < 300:
        return "intermediate"
    else:
        return "advanced"

#generating dailies
def generate_dailies(language: str, level: str) -> dict:
    prompt = f"""Generate 10 flashcards for {language} language learning at {level} level.
    Return only a JSON array with this exact structure:
    {{
        "cards": [
            {{
                "new_concept": "concept in {language}",
                "concept_pronunciation": "pronunciation of the concept in english",
                "english": "english translation",
                "meaning": "detailed explanation",
                "example": "example sentence in {language}",
                "example_pronunciation": "pronunciation of the example sentence in english",
                "translation": "translation of the example sentence"
            }}
        ]
    }}"""
    response = model.generate_content(prompt)
    # Remove markdown formatting and clean the string
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    # Remove any extra newlines and spaces
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)


#generate word pairs for memory game
def generate_memory_pairs(language: str, level: str) -> dict:
    prompt = f"""Generate 10 word/phrase pairs for a memory matching game in {language} at {level} level so that the user is able to learn some good, effective things to say in that language.
    Return only a JSON object with this exact structure:
    {{
        "pairs": [
            [
                "word/phrase in {language}",
                "english translation",
                "english pronunciation of the word/phrase that can be easily read in english"
            ],
            ... (repeat for all 10 pairs)
        ]
    }}
    Make sure the words/phrases are appropriate for {level} level learners, and if you give phrases, don't make them too long. Also, make sure to give some phrases and some words."""
    
    response = model.generate_content(prompt)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)


def language_teaching_chat(language: str, user_query: str) -> dict:
    prompt = f"""As a language teaching assistant for {language}, respond to: {user_query}, with answers related to {language}.
    
    Return response in this JSON structure:
    {{
        "response": "small, brief explanation",
        "examples": "two small examples of usage of {user_query}",
        "interesting_facts": "two small interesting facts about {user_query}"
    }}
    
    Focus on providing clear explanations with practical examples."""
    
    response = model.generate_content(prompt)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)

def generate_tongue_twisters(language: str) -> dict:
    prompt = f"""Generate 5 fun and challenging tongue twisters in {language} at five different difficulty levels.
    
    Return only a JSON object with this structure:
    {{
        "tongue_twisters": [
            {{
                "text": "tongue twister in {language}",
                "pronunciation": "pronunciation guide",
                "translation": "english translation",
            }}
        ]
    }}"""
    
    response = model.generate_content(prompt)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)

#function to teach sentence transformations based on the sentence given by user
def analyze_speech_transcript(language: str, transcript: str) -> dict:
    prompt = f"""Analyze this {language} speech transcript: "{transcript}"
    
    Return only a JSON object with this exact structure:
    {{
        "original": "the transcript",
        "correct_form": "grammatically correct version",
        "alternatives": [
            "2 alternative ways to express the same meaning"
        ],
        "score": "rating from 1-10 based on grammar and natural flow",
    }}
    
    Focus on natural speech patterns and common expressions in {language}."""
    
    response = model.generate_content(prompt)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)
