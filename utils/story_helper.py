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


#generating stories
def generate_stories(language: str, level: str) -> dict:
    prompt = f"""Generate a 5-part story in {language} for {level} level language learners.
    Each part should be 2-3 sentences long and simple enough to be illustrated.
    Return only a JSON object with this exact structure:
    {{
        "title": "story title in {language}",
        "title_english": "story title in English",
        "parts": [
            {{
                "part_number": 1,
                "content": "story part in {language}",
                "translation": "english translation",
                "description": "scene description for AI illustration"
            }},
            ... (repeat for all 5 parts)
        ]
    }}"""
    
    response = model.generate_content(prompt)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)


async def generate_and_start_story(user_id: str, language: str, level: str) -> dict:
    story_data = generate_stories(language, level)
    
    # Delete all stories in active_stories collection for this user
    storydb.active_stories.delete_many({"user_id": user_id})
    
    story_doc = {
        "user_id": user_id,
        "language": language,
        "level": level,
        "title": story_data["title"],
        "title_english": story_data["title_english"],
        "created_at": datetime.utcnow(),
        "current_part": 1,
        "completed": False,
        "parts": [
            {
                "part_number": part["part_number"],
                "content": part["content"],
                "translation": part["translation"],
                "description": part["description"],
                "user_narration": None
            }
            for part in story_data["parts"]
        ]
    }
    
    result = storydb.active_stories.insert_one(story_doc)
    return {
        "story_id": str(result.inserted_id),
        "current_part": story_doc["parts"][0],
        "total_parts": 5
    }

def evaluate_user_narration(original_text: str, user_narration: str, language: str) -> dict:
    prompt = f"""Compare the following original text in {language} with user's narration:
    Original: {original_text}
    User's narration: {user_narration}
    
    Provide feedback in this JSON structure:
    {{
        "accuracy_score": "percentage between 0-100",
        "pronunciation_feedback": "specific pronunciation feedback",
        "grammar_feedback": "grammar correction points",
        "vocabulary_feedback": "vocabulary usage feedback",
        "improvement_areas": ["area1", "area2", "area3"],
        "positive_points": ["point1", "point2", "point3"]
    }}"""
    
    response = model.generate_content(prompt)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```json\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)

async def save_part_narration(user_id: str, transcription: str) -> dict:
    active_story = storydb.active_stories.find_one({"user_id": user_id})
    
    if not active_story:
        raise ValueError("No active story found")
    
    current_part = active_story["current_part"]
    
    # Handle the case when all parts are completed
    if current_part > 5:
        final_feedback = generate_final_feedback(active_story)
        storydb.active_stories.delete_many({"user_id": user_id})
        return {
            "status": "completed",
            "final_feedback": final_feedback
        }

    original_part = active_story["parts"][current_part - 1]
    
    feedback = evaluate_user_narration(
        original_part["content"],
        transcription,
        active_story["language"]
    )
    
    narration_data = {
        "transcription": transcription,
        "recorded_at": datetime.utcnow(),
        "feedback": feedback
    }
    
    next_part = current_part + 1
    update_data = {
        "$set": {
            f"parts.{current_part - 1}.user_narration": narration_data,
            "current_part": next_part
        }
    }
    
    storydb.active_stories.update_one({"user_id": user_id}, update_data)
    
    # If we've just completed part 5, return completed status
    if next_part > 5:
        final_feedback = generate_final_feedback(active_story)
        storydb.active_stories.delete_many({"user_id": user_id})
        return {
            "status": "completed",
            "final_feedback": final_feedback
        }
    
    # Return the next part if story is still in progress
    return {
        "status": "in_progress",
        "next_part": active_story["parts"][next_part - 1],
        "current_feedback": feedback
    }


def generate_final_feedback(story: dict) -> dict:
    all_parts = [part for part in story["parts"] if part.get("user_narration")]
    prompt = f"""Analyze overall language learning performance across these 5 story parts:
    Original story: {[part["content"] for part in story["parts"]]}
    User narrations: {[part["user_narration"]["transcription"] for part in all_parts]}
    
    Provide final feedback in this JSON structure:
    {{
        "overall_score": "percentage between 0-100",
        "key_strengths": ["strength1", "strength2"],
        "main_improvement_areas": ["area1", "area2"],
        "learning_recommendations": ["recommendation1", "recommendation2"]
    }}"""
    
    response = model.generate_content(prompt)
    print(response.text)
    cleaned_text = response.text.strip()
    cleaned_text = cleaned_text.replace('```\n', '').replace('\n```', '')
    cleaned_text = ''.join(line.strip() for line in cleaned_text.splitlines())
    
    return json.loads(cleaned_text)
