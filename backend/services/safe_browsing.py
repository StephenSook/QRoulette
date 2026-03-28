# Google safe browsing API
# backend/services/safe_browsing.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()
GOOGLE_SAFE_BROWSING_API = os.getenv("GOOGLE_SAFE ")