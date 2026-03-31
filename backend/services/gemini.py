def summarize_risk(url: str, risk_level: str, reasons: list[str]) -> str:
    """
    Build a deterministic summary until Gemini API integration is fully wired.
    """
    if not reasons:
        return f"{url} appears {risk_level} with no specific indicators."
    top_reasons = "; ".join(reasons[:3])
    return f"{url} is classified as {risk_level}. Key indicators: {top_reasons}."
