# redirect chain checkers

# backend/services/redirect_checker.py

import requests

# Optional: you can use httpstatus.io API here instead of requests if you want
# API_URL = "https://api.httpstatus.io/v2/check"
# API_KEY = os.getenv("HTTPSTATUS_API_KEY")

def get_redirect_chain(url: str, max_hops: int = 6) -> dict:
    """
    Get the redirect chain for a URL and score it.
    Returns:
    {
        "score": int,
        "flags": list[str],
        "chain": list[str]  # full list of URLs including final destination
    }
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        # Gather full redirect chain
        chain = [resp.url for resp in response.history]
        chain.append(response.url)  # final URL

        score = 0
        flags = []

        hops = len(chain) - 1  # number of redirects

        # Scoring based on typical quishing behavior
        if hops <= 2:
            score += 0  # likely safe
        elif 3 <= hops <= 5:
            score += 2  # suspicious / marketing redirects
            flags.append(f"Redirect chain has {hops} hops — unusual")
        elif hops > 5:
            score += 3  # highly suspicious
            flags.append(f"Redirect chain has {hops} hops — potentially phishing/quishing")

        return {"score": score, "flags": flags, "chain": chain}

    except requests.RequestException as e:
        return {"score": 1, "flags": [f"Redirect check failed: {e}"], "chain": []}