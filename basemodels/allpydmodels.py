from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class InfoDict(BaseModel):
    language: str
    username: str

class ScoreDict(BaseModel):
    language: str
    username: str
    score: int

class StoryStart(BaseModel):
    language: str
    username: str

class StoryNarrate(BaseModel):
    transcription: str
    username: str

class NarrationFeedback(BaseModel):
    accuracy_score: float
    pronunciation_feedback: str
    grammar_feedback: str
    vocabulary_feedback: str
    improvement_areas: List[str]
    positive_points: List[str]

class StoryPart(BaseModel):
    part_number: int
    content: str
    translation: str
    description: str
    user_narration: Optional[dict]

class ActiveStory(BaseModel):
    user_id: str
    language: str
    level: str
    title: str
    title_english: str
    created_at: datetime
    current_part: int
    completed: bool
    parts: List[StoryPart]

class LanguageTeaching(BaseModel):
    language: str
    query: str

class TongueTwister(BaseModel):
    language: str

class AnalyzeSpeech(BaseModel):
    language: str
    transcription: str
    username: str