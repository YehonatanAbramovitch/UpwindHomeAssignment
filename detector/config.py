"""Every number and list the detector uses lives in this file.

Making the detector stricter or more relaxed only requires editing this file,
never the check logic.
"""

# --- Risk scoring -----------------------------------------------------------
# Every rule belongs to one of three severity levels. 
# The level answers one question: how likely is a legitimate email to break this rule?
HIGH = 30  # almost never appears in a legitimate email
MEDIUM = 20  # suspicious, but has legitimate uses
LOW = 10  # appears fairly often in legitimate email

# The risk score is the sum of the points of all detected rules (each rule
# counts once per email), capped at MAX_SCORE.
MAX_SCORE = 100
SUSPICIOUS_THRESHOLD = 30  # score >= 30 -> "Suspicious"
PHISHING_THRESHOLD = 60  # score >= 60 -> "Likely phishing"

RULE_POINTS = {
    # Suspicious links
    "link_public_ip": HIGH,
    "link_at_sign": HIGH,
    "link_text_mismatch": HIGH,
    "link_lookalike_domain": HIGH,
    "link_brand_misplaced": HIGH,
    "link_unusual_tld": MEDIUM,
    "link_shortener": MEDIUM,
    "link_long_structure": LOW,
    "link_no_encryption": LOW,
    # Spoofed sender
    "sender_name_domain_mismatch": HIGH,
    "sender_lookalike_domain": HIGH,
    "sender_name_is_other_address": HIGH,
    "sender_auth_failed": HIGH,
    "sender_brand_before_at": MEDIUM,
    "sender_reply_to_other_domain": MEDIUM,
    "sender_unusual_tld": MEDIUM,
    # Suspicious wording. Keyword matching cannot understand context, so no
    # wording category is trusted more than another: they are all LOW.
    "wording_time_pressure": LOW,
    "wording_threat": LOW,
    "wording_sensitive_info": LOW,
    "wording_prize_or_refund": LOW,
    "wording_payment_demand": LOW,
    "wording_generic_greeting": LOW,
    "wording_install_or_permissions": LOW,
    "wording_shouting": LOW,
    # Attachments
    "attachment_runs_code": HIGH,
    "attachment_disguised_name": HIGH,
    "attachment_macro": MEDIUM,
    "attachment_html": MEDIUM,
    "attachment_archive": LOW,
    # History of previous scans
    "history_sender": MEDIUM,
    "history_link_domain": MEDIUM,
}

# --- Domains ----------------------------------------------------------------
# Organizations that phishing emails commonly imitate.
# Key: the name as it appears in a display name or inside a URL.
# Value: the domains the organization really owns (subdomains are included).
KNOWN_BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "whatsapp": {"whatsapp.com"},
    "github": {"github.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    # Israeli organizations and government bodies
    "leumi": {"leumi.co.il"},
    "hapoalim": {"bankhapoalim.co.il"},
    "isracard": {"isracard.co.il"},
    "israel post": {"israelpost.co.il"},
    "gov.il": {"gov.il"},
    "בנק לאומי": {"leumi.co.il"},
    "בנק הפועלים": {"bankhapoalim.co.il"},
    "דואר ישראל": {"israelpost.co.il"},
    "ביטוח לאומי": {"gov.il"},
    "רשות המסים": {"gov.il"},
    "משרד הבריאות": {"gov.il"},
}

# Characters that are used to imitate other letters: "paypa1" looks like "paypal".
# The replacement is applied to both sides of a comparison, the checked name
# and the brand name. "1", "i" and "l" all become "l", so "netfl1x" and
# "netflix" both turn into "netfllx" and are recognized as lookalikes.
LOOKALIKE_CHARACTERS = {
    "0": "o",
    "1": "l",
    "i": "l",
    "3": "e",
    "5": "s",
    "rn": "m",
    "vv": "w",
}

# Domain endings that are cheap or free to register and are heavily abused.
UNUSUAL_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work",
    "zip", "mov", "icu", "cyou", "cfd", "sbs", "rest", "buzz", "monster",
    "quest", "loan", "download", "review", "stream", "party", "gdn",
}

# Public suffixes made of two parts. "bank.co.il" is one registered domain,
# not a subdomain of "co.il".
TWO_PART_SUFFIXES = {
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "com.br", "co.jp", "co.in", "co.za", "com.tr", "com.mx",
}

# --- Suspicious links -------------------------------------------------------
# Services that hide the real destination of a link.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "rb.gy", "shorturl.at", "s.id",
}

# A link is "long and convoluted" when it has more subdomains than this, or
# the whole URL is longer than MAX_URL_LENGTH characters.
# Subdomains are the parts in front of the registered domain, and "www" is
# not counted:
#   www.login.leumi.co.il                    -> 1 (login)                   fine
#   login.secure.account.update.example.com  -> 4 (login, secure, account,
#                                                  update)                  flagged
MAX_SUBDOMAINS = 2
MAX_URL_LENGTH = 200

# Link text that ends like this is a file name ("report.pdf"), not a web site.
FILE_NAME_ENDINGS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "zip",
    "html", "htm", "png", "jpg", "jpeg",
}

# --- Suspicious wording -----------------------------------------------------
# One list of phrases per category, in English and Hebrew. 
# A category is detected when at least one of its phrases appears in the subject or body.
WORDING_PHRASES = {
    "wording_time_pressure": [
        "urgent", "immediately", "right away", "as soon as possible",
        "within 24 hours", "within 48 hours", "expires today", "last chance",
        "act now", "final notice",
        "דחוף", "מיידי", "באופן מיידי", "תוך 24 שעות", "תוך 48 שעות",
        "הזדמנות אחרונה", "פג תוקף היום", "הודעה אחרונה",
    ],
    "wording_threat": [
        "will be suspended", "will be locked", "will be closed", "will be deleted",
        "will be terminated", "has been suspended", "has been limited",
        "legal action", "unauthorized access", "unusual activity",
        "ייחסם", "יושעה", "ייסגר", "יימחק", "הושעה", "נחסם",
        "הליכים משפטיים", "פעילות חריגה", "גישה לא מורשית",
    ],
    "wording_sensitive_info": [
        "verify your password", "confirm your password", "enter your password",
        "verify your account", "confirm your identity", "verification code",
        "one-time code", "card number", "credit card details", "bank account details",
        "social security number", "update your billing",
        "אמת את הסיסמה", "הזן את הסיסמה", "אמת את החשבון", "אימות זהות",
        "קוד אימות", "קוד חד פעמי", "מספר כרטיס", "פרטי כרטיס האשראי",
        "פרטי חשבון הבנק", "מספר תעודת זהות",
    ],
    "wording_prize_or_refund": [
        "you have won", "you won", "congratulations", "claim your prize",
        "lottery", "free gift", "refund",
        "זכית", "מזל טוב", "ממתין לך פרס", "מתנה חינם", "זיכוי",
        # "החזר" alone would also match "החזרת מוצר" (sending a product back),
        # so it is used only in phrases that are about money.
        "החזר מס", "החזר כספי",
        # With the definite article ("ה"), the same phrases change form.
        "החזר המס", "החזר הכספי",
    ],
    "wording_payment_demand": [
        "outstanding payment", "overdue invoice", "unpaid invoice", "payment is due",
        "wire transfer", "gift card", "gift cards", "bitcoin", "pay the fee",
        "customs fee", "delivery fee",
        "חוב פתוח", "חשבונית שלא שולמה", "יתרת חוב", "העברה בנקאית",
        "כרטיס מתנה", "כרטיסי מתנה", "דמי משלוח", "דמי מכס", "תשלום נדרש",
    ],
    "wording_generic_greeting": [
        "dear customer", "dear user", "dear client", "dear member",
        "dear account holder", "dear sir or madam", "valued customer",
        "לקוח יקר", "לקוחה יקרה", "משתמש יקר", "לקוח נכבד",
    ],
    "wording_install_or_permissions": [
        "install the app", "install the attached", "download the app",
        "download and install", "enable macros", "enable content", "enable editing",
        "allow access", "grant access", "remote access", "anydesk", "teamviewer",
        "התקן את האפליקציה", "הורד את האפליקציה", "הורד והתקן",
        "אפשר תוכן", "אפשר עריכה", "אשר גישה", "אשר הרשאות", "שליטה מרחוק",
    ],
}

# "Shouting" style: at least this many words written entirely in capital letters, or a run of this many exclamation marks.
SHOUTING_MIN_CAPITAL_WORDS = 3
SHOUTING_MIN_EXCLAMATION_RUN = 3

# --- Attachments ------------------------------------------------------------
# Files that run code when opened: programs, scripts and shortcuts.
CODE_EXTENSIONS = {
    "exe", "scr", "msi", "bat", "cmd", "com", "pif", "vbs", "js", "jse",
    "wsf", "ps1", "jar", "hta", "lnk",
}

# Ordinary document and picture types. 
# One of these right before a code extension ("invoice.pdf.exe") means the name pretends to be a harmless file.
DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "jpg", "jpeg", "png", "gif", "mp3", "mp4",
}

MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm"}
HTML_EXTENSIONS = {"html", "htm", "shtml"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "iso", "img"}

# Hidden characters that reverse the display order of a file name.
DIRECTION_OVERRIDE_CHARACTERS = {"‮", "‭", "⁦", "⁧", "⁨"}

# At least this many spaces in a row inside a file name can push the real extension out of view: "report.pdf      .exe".
MIN_SPACE_RUN_IN_FILE_NAME = 3
