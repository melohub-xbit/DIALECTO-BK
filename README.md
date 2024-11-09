# Dialecto - Language Learning App

This repository contains the backend code for Dialecto, a web application designed to help users learn new languages in a fun and engaging way. 

## Project Structure

The project is structured as follows:
```
DIALECTO-BK/
├── basemodels/
│   └── allpydmodels.py
├── endpoints/
│   ├── auth.py
│   ├── games.py
│   └── games_word.py
├── utils/
│   ├── all_helper.py
│   └── story_helper.py
├── main.py
├── database.py
├── .gitignore
└── requirements.txt
```

**utils:**
- **all_helper.py:** Contains utility functions used throughout the backend.
- **story_helper.py:** Contains functions related to story generation and learning.

**endpoints:**
- **auth.py:** Handles user authentication (login, registration, logout).
- **games.py:** Contains endpoints for gamified features, including leaderboards, point updates, and game logic.
- **games_word.py:** Contains endpoints for word-based games, such as flashcard generation, memory games, and speech analysis.

**basemodels:**
- **allpydmodels.py:** Defines data models used throughout the backend.

**main.py:** The main entry point for the backend application.

**database.py:** Handles database interactions.

**requirements.txt:** Lists the required Python packages.

## Features

Dialecto offers a variety of features to help users learn new languages:

- **Gamified Learning:**
    - **Leaderboards:** Track user progress and compete with others.
    - **Point System:** Earn points for completing games and activities.
    - **Story Learning:** Learn new vocabulary and grammar through interactive stories.
    - **Flashcard Generation:** Create custom flashcards for daily learning.
    - **Memory Games:** Test your memory and vocabulary with fun memory games.
    - **Speech Analysis:** Get feedback on your pronunciation and fluency.
- **Chat Features:**
    - **Pixie:** A chatbot that provides explanations, usage examples, and interesting facts about words and phrases.
    - **Tongue Twister Generator:** Practice your pronunciation with tongue twisters.
    - **Grammar Buddy:** Get help with grammar and correct your sentences.

## Deployment

- **Backend:** Deployed on Render at [https://dialecto.onrender.com](https://dialecto.onrender.com).
- **Frontend:** Deployed on Vercel at [https://dialecto-nine.vercel.app/](https://dialecto-nine.vercel.app/).

## Getting Started

To run the backend locally:

1. Clone the repository, and in the root directory of the repo, install Python and the required packages:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn main:app --reload
   ```

### The backend will be accessible at `http://127.0.0.1:8000` or the link given in the terminal. To also run the frontend, follow the instructions in the frontend repository: https://github.com/CShah44/Dialecto.git