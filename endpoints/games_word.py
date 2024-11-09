from fastapi import *
from basemodels.allpydmodels import *
from utils.all_helper import *
from utils.story_helper import *
from database import *

router = APIRouter()

@router.post("/dailies")
async def dailies(info_dict: InfoDict):
    language = info_dict.language.upper()
    current_user = info_dict.username
    #get points of the user with the current_user username for language from the database
    user_points = users_collection.find_one({"username": current_user})["languages"][language]
    level = determine_user_level(user_points)
    try:
        dailies_data = generate_dailies(language, level)
        return {
            "dailies": dailies_data
        }
    except:
        print("Error generating dailies")

@router.post("/memorypairs")
async def memory_pairs(info_dict: InfoDict):
    language = info_dict.language.upper()
    current_user = info_dict.username
    user_points = users_collection.find_one({"username": current_user})["languages"][language]
    level = determine_user_level(user_points)
    
    try:
        pairs_data = generate_memory_pairs(language, level)
        return {
            "words": pairs_data
        }
    except:
        return {
            "pairs": []
        }


@router.post("/language_teacher")
async def chat_with_language_teacher(
    info_dict: LanguageTeaching,
):
    try:
        response = language_teaching_chat(info_dict.language, info_dict.query)
        return {"data": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/tongue_twisters")
async def get_tongue_twisters(
    info_dict: TongueTwister,
):
    try:
        twisters = generate_tongue_twisters(language=info_dict.language)
        return {"data": twisters}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/speech_analysis")
async def analyze_speech(info_dict: AnalyzeSpeech):
    language = info_dict.language.upper()
    transcript = info_dict.transcription
    current_user = info_dict.username
    analysis_result = analyze_speech_transcript(language, transcript)
    
    # Update user's points based on the speech score
    score_to_add = int(analysis_result["score"])
    if score_to_add < 8:
        score_to_add = 0
    elif score_to_add >= 8 and score_to_add <= 10:
        score_to_add = 2
    users_collection.update_one(
        {"username": current_user},
        {"$inc": {f"languages.{language}": score_to_add}}
    )
    
    return analysis_result
