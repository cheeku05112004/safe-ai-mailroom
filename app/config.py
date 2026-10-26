import os
from dotenv import load_dotenv

load_dotenv()

MODEL_BASE_URL = os.getenv(
    "MODEL_BASE_URL",
    "https://aipipe.org/openai/v1"
).rstrip("/")

MODEL_API_KEY = os.getenv("MODEL_API_KEY", "")

MODEL_NAME = os.getenv(
    "MODEL_NAME",
    "gpt-5-nano"
)

if not MODEL_API_KEY:
    raise RuntimeError("AI Pipe API token is missing!")

