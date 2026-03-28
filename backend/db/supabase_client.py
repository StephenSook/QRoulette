import os

from dotenv import load_dotenv
from supabase import Client, create_client

# Load local .env for dev; production should inject env vars directly.
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_KEY in environment.")

# Shared singleton client used across DB helper modules.
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
