from urllib.parse import urlparse

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".msi",
    ".dmg",
    ".pkg",
    ".apk",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".zip",
    ".pif",
    ".iso",
    ".jar",
    ".ws",
    ".app",
    ".command",
    ".sh",
    ".rb",
    ".py",
    ".docm",
    ".xlsm",
    ".pptm",
    ".lnk",
    ".hta",
    ".cpl",
    ".gadget",
    ".vb",
    ".wsf",
    ".hta",
    ".reg",
    ".scf"
}


def get_suspicious_extension(url: str) -> str | None:
    path = (urlparse(url).path or "").lower()
    if "." not in path:
        return None
    ext = "." + path.rsplit(".", 1)[-1]
    return ext if ext in SUSPICIOUS_EXTENSIONS else None
