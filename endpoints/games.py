from fastapi import *
from basemodels.allpydmodels import *
from utils.all_helper import *
from database import *

router = APIRouter()

@router.post("/leaderboard")
async def leaderboard(info_dict: InfoDict):
    language = info_dict.language.upper()

    try:    
        # Find users who have points in the specified language
        pipeline = [
            {"$match": {f"languages.{language}": {"$exists": True}}},
            {"$project": {
                "_id": 0,
                "username": 1,
                "points": f"$languages.{language}"
            }},
            {"$sort": {"points": -1}},
            {"$group": {
                "_id": None,
                "users": {"$push": "$$ROOT"}
            }},
            {"$unwind": {"path": "$users", "includeArrayIndex": "rank"}},
            {"$project": {
                "_id": 0,
                "username": "$users.username",
                "points": "$users.points",
                "rank": {"$add": ["$rank", 1]}
            }}
        ]
    
        leaderboard_users = list(users_collection.aggregate(pipeline))
        return {
            "language": language,
            "leaderboard": leaderboard_users
        }
    except:
        return{
            "language": language,
            "leaderboard": []
        }

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
    
@router.post("/updatescore")
async def update_score(info_dict: ScoreDict):
    language = info_dict.language.upper()
    score = info_dict.score
    current_user = info_dict.username
    #update the current user's points in the database
    users_collection.update_one(
        {"username": current_user},
        {"$inc": {f"languages.{language}": score}}
    )

@router.post("/getscores")
async def get_scores(info_dict: InfoDict):
    #get the languages dict from the database of the current user
    current_user = info_dict.username
    user_languages = users_collection.find_one({"username": current_user})["languages"]
    try:
        return {
            "languages": user_languages
        }
    except:
        return {
            "languages": {}
        }

#endpoint for story based learning
@router.post("/storystart")
async def start_story(info_dict: StoryStart):
    language = info_dict.language.upper()
    current_user = info_dict.username
    #get points of the user with the current_user username for language from the database
    user_points = users_collection.find_one({"username": current_user})["languages"][language]
    user_id = users_collection.find_one({"username": current_user})["_id"]
    level = determine_user_level(user_points)
    try:
        return await generate_and_start_story(user_id, language, level)
    except:
        print("Error generating story")

@router.post("/storynarrate")
async def submit_narration(info_dict: StoryNarrate):
    transcription = info_dict.transcription
    current_user = info_dict.username
    user_id = users_collection.find_one({"username": current_user})["_id"]
    return await save_part_narration(user_id,  transcription)