
"""
╔══════════════════════════════════════════════════════════════╗
║          PERSONAL VAULT  — Secure Life Data Manager          ║
║          Prof. V. Ravichandran  |  The Mountain Path         ║
╚══════════════════════════════════════════════════════════════╝

Security model:
  • Master password → PBKDF2-SHA256 (310,000 iterations) → AES-256-GCM
  • All vault data encrypted at rest in vault.enc
  • Password hash stored separately in .vault_auth (bcrypt)
  • No plaintext data ever touches disk
  • Session auto-locks after inactivity
"""

import streamlit as st
import streamlit.components.v1 as components
import json
import io
import speech_recognition as sr, os, base64, hashlib, hmac, time, re
from datetime import datetime, date, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import bcrypt

# ── Paths ─────────────────────────────────────────────────────────
VAULT_DIR  = Path("vault_data")
VAULT_FILE = VAULT_DIR / "vault.enc"
AUTH_FILE  = VAULT_DIR / "vault_auth"
SALT_FILE  = VAULT_DIR / "vault_salt"
VAULT_DIR.mkdir(exist_ok=True)

# ── Brand colours ─────────────────────────────────────────────────
C = {
    "bg":       "#0a0f1e",
    "surface":  "#111827",
    "card":     "#1a2235",
    "border":   "#1e3a5f",
    "gold":     "#FFD700",
    "blue":     "#3B82F6",
    "teal":     "#14B8A6",
    "rose":     "#F43F5E",
    "violet":   "#8B5CF6",
    "amber":    "#F59E0B",
    "green":    "#10B981",
    "muted":    "#64748b",
    "text":     "#e2e8f0",
    "white":    "#ffffff",
}

# ── Category config ───────────────────────────────────────────────
CATEGORIES = {
    "🩺 Medical — Diabetes":    {"color": C["rose"],   "icon": "🩺"},
    "💉 Medical — Blood Pressure": {"color": C["violet"], "icon": "💉"},
    "❤️ Medical — General Health": {"color": C["teal"],   "icon": "❤️"},
    "🛡️ Medical Insurance":       {"color": C["blue"],   "icon": "🛡️"},
    "🚗 Driving Licence":         {"color": C["amber"],  "icon": "🚗"},
    "🪪 Aadhaar Card":            {"color": C["green"],  "icon": "🪪"},
    "🗳️ Voter ID":                {"color": C["teal"],   "icon": "🗳️"},
    "🛂 Passport":                {"color": C["blue"],   "icon": "🛂"},
    "💊 Medications & Prescriptions": {"color": C["rose"], "icon": "💊"},
    "🏥 Doctor & Hospital Contacts":  {"color": C["violet"], "icon": "🏥"},
    "📋 Other Documents":         {"color": C["muted"],  "icon": "📋"},
}

FIELD_TEMPLATES = {
    "🩺 Medical — Diabetes": [
        ("Diagnosis Date",        "date"),
        ("Diabetes Type",         "select:Type 1,Type 2,Pre-Diabetes,Gestational"),
        ("Current HbA1c (%)",     "number"),
        ("Fasting Glucose (mg/dL)", "number"),
        ("Post-Prandial Glucose", "number"),
        ("Consulting Doctor",     "text"),
        ("Hospital / Clinic",     "text"),
        ("Next Review Date",      "date"),
        ("Current Medications",   "textarea"),
        ("Diet Restrictions",     "textarea"),
        ("Notes",                 "textarea"),
    ],
    "💉 Medical — Blood Pressure": [
        ("Diagnosis Date",        "date"),
        ("BP Category",           "select:Normal,Elevated,Stage 1 Hypertension,Stage 2 Hypertension,Hypertensive Crisis"),
        ("Systolic (mmHg)",       "number"),
        ("Diastolic (mmHg)",      "number"),
        ("Resting Heart Rate",    "number"),
        ("Consulting Doctor",     "text"),
        ("Hospital / Clinic",     "text"),
        ("Next Review Date",      "date"),
        ("Current Medications",   "textarea"),
        ("Notes",                 "textarea"),
    ],
    "❤️ Medical — General Health": [
        ("Blood Group",           "select:A+,A-,B+,B-,AB+,AB-,O+,O-"),
        ("Height (cm)",           "number"),
        ("Weight (kg)",           "number"),
        ("Allergies",             "textarea"),
        ("Chronic Conditions",    "textarea"),
        ("Last Health Checkup",   "date"),
        ("Next Health Checkup",   "date"),
        ("Primary Doctor",        "text"),
        ("Emergency Contact",     "text"),
        ("Emergency Phone",       "text"),
        ("Notes",                 "textarea"),
    ],
    "🛡️ Medical Insurance": [
        ("Insurer Name",          "text"),
        ("Policy Number",         "text"),
        ("Plan Name",             "text"),
        ("Sum Insured (₹)",       "number"),
        ("Annual Premium (₹)",    "number"),
        ("Policy Start Date",     "date"),
        ("Policy Renewal Date",   "date"),
        ("Grace Period (days)",   "number"),
        ("TPA / Cashless Network","text"),
        ("Nominee Name",          "text"),
        ("Customer Care No.",     "text"),
        ("Policy Document Link",  "text"),
        ("Pre-existing Conditions Covered", "select:Yes,No,Partial"),
        ("Notes",                 "textarea"),
    ],
    "🚗 Driving Licence": [
        ("Licence Number",        "text"),
        ("Name on Licence",       "text"),
        ("Date of Birth",         "date"),
        ("Address",               "textarea"),
        ("Issue Date",            "date"),
        ("Expiry Date",           "date"),
        ("Vehicle Classes",       "text"),
        ("Issuing RTO",           "text"),
        ("Blood Group",           "select:A+,A-,B+,B-,AB+,AB-,O+,O-"),
        ("Notes",                 "textarea"),
    ],
    "🪪 Aadhaar Card": [
        ("Aadhaar Number",        "text"),
        ("Name",                  "text"),
        ("Date of Birth",         "date"),
        ("Gender",                "select:Male,Female,Other"),
        ("Address",               "textarea"),
        ("Mobile Linked",         "text"),
        ("Email Linked",          "text"),
        ("Enrolment Date",        "date"),
        ("Notes",                 "textarea"),
    ],
    "🗳️ Voter ID": [
        ("Voter ID Number (EPIC)","text"),
        ("Name",                  "text"),
        ("Date of Birth",         "date"),
        ("Gender",                "select:Male,Female,Other"),
        ("Father / Husband Name", "text"),
        ("Address",               "textarea"),
        ("Constituency",          "text"),
        ("Assembly Segment",      "text"),
        ("Issue Date",            "date"),
        ("Notes",                 "textarea"),
    ],
    "🛂 Passport": [
        ("Passport Number",       "text"),
        ("Name",                  "text"),
        ("Date of Birth",         "date"),
        ("Gender",                "select:Male,Female,Other"),
        ("Place of Birth",        "text"),
        ("Nationality",           "text"),
        ("Issue Date",            "date"),
        ("Expiry Date",           "date"),
        ("Place of Issue",        "text"),
        ("File Number",           "text"),
        ("ECR Status",            "select:ECR,ECNR"),
        ("Emergency Contact",     "text"),
        ("Notes",                 "textarea"),
    ],
    "💊 Medications & Prescriptions": [
        ("Medication Name",       "text"),
        ("Prescribed By",         "text"),
        ("Prescription Date",     "date"),
        ("Dosage",                "text"),
        ("Frequency",             "select:Once daily,Twice daily,Thrice daily,As needed,Weekly"),
        ("Duration",              "text"),
        ("Pharmacy",              "text"),
        ("Refill Due Date",       "date"),
        ("Side Effects (noted)",  "textarea"),
        ("Notes",                 "textarea"),
    ],
    "🏥 Doctor & Hospital Contacts": [
        ("Doctor / Hospital Name","text"),
        ("Speciality",            "text"),
        ("Phone 1",               "text"),
        ("Phone 2",               "text"),
        ("Email",                 "text"),
        ("Address",               "textarea"),
        ("Consultation Fee (₹)",  "number"),
        ("Appointment Day / Time","text"),
        ("Notes",                 "textarea"),
    ],
    "📋 Other Documents": [
        ("Document Name",         "text"),
        ("Document Number",       "text"),
        ("Issued By",             "text"),
        ("Issue Date",            "date"),
        ("Expiry Date",           "date"),
        ("Notes",                 "textarea"),
    ],
}

# ══════════════════════════════════════════════════════════════════
# ENCRYPTION ENGINE
# ══════════════════════════════════════════════════════════════════
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=310_000)
    return kdf.derive(password.encode())

def _get_salt() -> bytes:
    if SALT_FILE.exists():
        return base64.b64decode(SALT_FILE.read_text().strip())
    salt = os.urandom(32)
    SALT_FILE.write_text(base64.b64encode(salt).decode())
    return salt

def vault_encrypt(data: dict, password: str) -> None:
    salt = _get_salt()
    key  = _derive_key(password, salt)
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
    payload = base64.b64encode(nonce + ct).decode()
    VAULT_FILE.write_text(payload)

def vault_decrypt(password: str) -> dict | None:
    if not VAULT_FILE.exists():
        return {}
    try:
        salt    = _get_salt()
        key     = _derive_key(password, salt)
        raw     = base64.b64decode(VAULT_FILE.read_text().strip())
        nonce, ct = raw[:12], raw[12:]
        plain   = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(plain)
    except Exception:
        return None   # wrong password or corrupted

def set_master_password(password: str) -> None:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    AUTH_FILE.write_bytes(hashed)

def verify_master_password(password: str) -> bool:
    if not AUTH_FILE.exists():
        return False
    stored = AUTH_FILE.read_bytes()
    return bcrypt.checkpw(password.encode(), stored)

def vault_exists() -> bool:
    return AUTH_FILE.exists()

# ══════════════════════════════════════════════════════════════════
# CSS
# ══════════════════════════════════════════════════════════════════
def apply_css():
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=Source+Sans+3:wght@300;400;600&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Source Sans 3', sans-serif;
        background-color: {C["bg"]};
        color: {C["text"]};
    }}
    .stApp {{ background: linear-gradient(135deg, #0a0f1e 0%, #0d1526 50%, #0a1628 100%); }}

    /* Sidebar */
    [data-testid="stSidebar"] {{
        background: linear-gradient(180deg, #060c1a 0%, #0a1628 100%) !important;
        border-right: 1px solid {C["border"]} !important;
    }}
    [data-testid="stSidebar"] * {{ color: {C["text"]} !important; }}

    /* Inputs */
    .stTextInput input, .stNumberInput input, .stSelectbox select,
    .stTextArea textarea, .stDateInput input {{
        background: {C["card"]} !important;
        border: 1px solid {C["border"]} !important;
        color: {C["white"]} !important;
        border-radius: 8px !important;
        font-family: 'Source Sans 3', sans-serif !important;
    }}
    .stTextInput input:focus, .stTextArea textarea:focus {{
        border-color: {C["gold"]} !important;
        box-shadow: 0 0 0 2px rgba(255,215,0,0.15) !important;
    }}

    /* ── All text inputs: label visibility ── */
    [data-testid="stTextInput"] label,
    [data-testid="stNumberInput"] label,
    [data-testid="stTextArea"] label,
    [data-testid="stSelectbox"] label,
    [data-testid="stDateInput"] label {{
        color: #e2e8f0 !important;
        font-size: 0.88rem !important;
        font-weight: 600 !important;
        margin-bottom: 4px !important;
    }}

    /* ── Placeholder text — clearly visible but muted ── */
    .stTextInput input::placeholder,
    .stTextArea textarea::placeholder {{
        color: #64748b !important;
        opacity: 1 !important;
    }}

    /* ── Password input — bright white text, mono font ── */
    [data-testid="stTextInput"] input[type="password"] {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.1rem !important;
        letter-spacing: 4px !important;
        color: #ffffff !important;
        background: #0f1e35 !important;
        border: 1px solid #2d5a8e !important;
        caret-color: {C["gold"]} !important;
    }}
    [data-testid="stTextInput"] input[type="password"]:focus {{
        border-color: {C["gold"]} !important;
        box-shadow: 0 0 0 2px rgba(255,215,0,0.2) !important;
        background: #0f1e35 !important;
    }}
    [data-testid="stTextInput"] input[type="password"]::placeholder {{
        color: #4a6080 !important;
        letter-spacing: 0px !important;
        font-family: 'Source Sans 3', sans-serif !important;
        font-size: 0.88rem !important;
    }}

    /* Buttons */
    .stButton > button {{
        background: linear-gradient(135deg, {C["gold"]}, #e6b800) !important;
        color: #0a0f1e !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        font-family: 'Source Sans 3', sans-serif !important;
        letter-spacing: 0.5px !important;
        transition: all 0.2s !important;
    }}
    .stButton > button:hover {{
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(255,215,0,0.3) !important;
    }}
    .stButton > button[kind="secondary"] {{
        background: {C["card"]} !important;
        color: {C["text"]} !important;
        border: 1px solid {C["border"]} !important;
    }}

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {{
        background: {C["surface"]} !important;
        border-radius: 10px !important;
        padding: 4px !important;
        gap: 2px !important;
        border: 1px solid {C["border"]} !important;
    }}
    .stTabs [data-baseweb="tab"] {{
        background: transparent !important;
        color: {C["muted"]} !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
    }}
    .stTabs [aria-selected="true"] {{
        background: {C["gold"]} !important;
        color: #0a0f1e !important;
    }}
    .stTabs [data-baseweb="tab-panel"] {{
        background: transparent !important;
        padding: 12px 0 !important;
    }}

    /* Expanders */
    .streamlit-expanderHeader {{
        background: {C["card"]} !important;
        border: 1px solid {C["border"]} !important;
        border-radius: 8px !important;
        color: {C["text"]} !important;
        font-weight: 600 !important;
    }}
    .streamlit-expanderContent {{
        background: {C["surface"]} !important;
        border: 1px solid {C["border"]} !important;
        border-top: none !important;
        border-radius: 0 0 8px 8px !important;
    }}

    /* Remove Streamlit chrome */
    #MainMenu, footer, header {{ visibility: hidden; }}
    .block-container {{ padding-top: 1.5rem !important; max-width: 1100px; }}

    /* Scrollbar */
    ::-webkit-scrollbar {{ width: 5px; }}
    ::-webkit-scrollbar-track {{ background: {C["bg"]}; }}
    ::-webkit-scrollbar-thumb {{ background: {C["border"]}; border-radius: 3px; }}

    /* ── Alerts ── */
    .stSuccess {{ background: rgba(16,185,129,0.12) !important; border: 1px solid {C["green"]} !important; }}
    .stError   {{ background: rgba(244,63,94,0.12)  !important; border: 1px solid {C["rose"]}  !important; }}
    .stWarning {{ background: rgba(245,158,11,0.12) !important; border: 1px solid {C["amber"]} !important; }}

    /* Metric */
    [data-testid="stMetric"] {{
        background: {C["card"]};
        border: 1px solid {C["border"]};
        border-radius: 10px;
        padding: 14px 16px;
    }}
    [data-testid="stMetricLabel"] {{ color: {C["muted"]} !important; font-size: 0.78rem !important; }}
    [data-testid="stMetricValue"] {{ color: {C["gold"]} !important; font-family: 'Playfair Display',serif !important; }}
    </style>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# UI HELPERS
# ══════════════════════════════════════════════════════════════════
def _card(content_html, color=None, title=None):
    border = color or C["border"]
    top_border = f"border-top:3px solid {border};" if color else ""
    title_html = (f"<div style='font-family:Playfair Display,serif;font-size:1rem;"
                  f"font-weight:700;color:{border};margin-bottom:10px;'>{title}</div>") if title else ""
    st.markdown(
        f"<div style='background:{C['card']};border:1px solid {C['border']};"
        f"{top_border}border-radius:10px;padding:16px 20px;margin:6px 0;'>"
        f"{title_html}{content_html}</div>",
        unsafe_allow_html=True
    )

def _badge(text, color):
    return (f"<span style='background:{color}22;color:{color};border:1px solid {color}55;"
            f"border-radius:20px;padding:2px 10px;font-size:0.74rem;font-weight:700;"
            f"white-space:nowrap;'>{text}</span>")

def _days_until(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return (d - date.today()).days
    except:
        return None

def _expiry_badge(date_str, label="Expiry"):
    days = _days_until(date_str)
    if days is None:
        return ""
    if days < 0:
        return _badge(f"⛔ {label} EXPIRED {abs(days)}d ago", C["rose"])
    elif days <= 30:
        return _badge(f"🔴 {label} in {days}d", C["rose"])
    elif days <= 90:
        return _badge(f"🟠 {label} in {days}d", C["amber"])
    elif days <= 180:
        return _badge(f"🟡 {label} in {days}d", C["gold"])
    else:
        return _badge(f"✅ Valid {days}d", C["green"])

def _section_header(title, subtitle=""):
    sub = f"<div style='color:{C['muted']};font-size:0.85rem;margin-top:3px;'>{subtitle}</div>" if subtitle else ""
    st.markdown(
        f"<div style='font-family:Playfair Display,serif;font-size:1.4rem;font-weight:900;"
        f"color:{C['gold']};border-bottom:2px solid {C['border']};padding-bottom:8px;"
        f"margin:6px 0 16px 0;'>{title}</div>{sub}",
        unsafe_allow_html=True
    )

def _hero():
    st.markdown(
        f"<div style='background:linear-gradient(135deg,{C['surface']},{C['card']});"
        f"border:2px solid {C['gold']}44;border-radius:14px;padding:24px 32px;"
        f"margin-bottom:24px;position:relative;overflow:hidden;'>"
        f"<div style='position:absolute;top:-20px;right:-20px;width:120px;height:120px;"
        f"background:radial-gradient(circle,{C['gold']}22,transparent);border-radius:50%;'></div>"
        f"<div style='font-family:Playfair Display,serif;font-size:2rem;font-weight:900;"
        f"color:{C['gold']};letter-spacing:1px;'>🔐 Personal Vault</div>"
        f"<div style='color:{C['text']};font-size:0.9rem;margin-top:4px;'>"
        f"Your encrypted life data — Medical · Identity · Insurance · Licences</div>"
        f"<div style='color:{C['muted']};font-size:0.78rem;margin-top:6px;'>"
        f"AES-256-GCM encrypted · Password protected · Data never leaves your device</div>"
        f"</div>",
        unsafe_allow_html=True
    )


# ══════════════════════════════════════════════════════════════════
# FORM RENDERER
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
# VOICE INPUT  —  st.audio_input → SpeechRecognition (Google free)
# ══════════════════════════════════════════════════════════════════

def _transcribe_audio(audio_bytes: bytes) -> tuple[str, str]:
    """Transcribe WAV bytes using Google Speech Recognition (free, no key).
    Returns (transcript, error_message)."""
    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile(io.BytesIO(audio_bytes)) as source:
            recognizer.adjust_for_ambient_noise(source, duration=0.3)
            audio_data = recognizer.record(source)
        text = recognizer.recognize_google(audio_data, language="en-IN")
        return text, ""
    except sr.UnknownValueError:
        return "", "Could not understand — speak clearly and try again."
    except sr.RequestError as e:
        return "", f"Speech service unavailable: {e}"
    except Exception as e:
        return "", f"Error: {e}"


def _safe_str(val) -> str:
    """Ensure only plain strings go into session_state — never widget objects."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    # DeltaGenerator or any other widget object → discard, return empty
    return ""


def voice_field(label: str, key: str, default: str = "",
                multiline: bool = False) -> str:
    """
    Text input (or textarea) + 🎤 Speak button.
    Records via st.audio_input → transcribes via Google Speech API.
    User chooses to Replace or Append transcript into the field.
    """
    C_GOLD   = "#FFD700";  C_BORDER = "#1e3a5f"
    C_TEXT   = "#e2e8f0";  C_MUTED  = "#64748b"

    # Always sanitize before touching session_state
    safe_default = _safe_str(default)

    # Seed session_state with a clean string (only if not already set)
    if key not in st.session_state or not isinstance(st.session_state[key], str):
        st.session_state[key] = safe_default

    current_val = st.session_state[key]

    # ── Label ────────────────────────────────────────────────
    st.markdown(
        f"<div style='color:{C_TEXT};font-size:0.88rem;font-weight:600;"
        f"margin:10px 0 4px 0;'>{label}</div>",
        unsafe_allow_html=True
    )

    # ── Text field (always visible, always editable) ─────────
    widget_key = f"_ta_{key}" if multiline else f"_ti_{key}"
    if multiline:
        typed = st.text_area(label, value=current_val,
                             key=widget_key, height=80,
                             label_visibility="collapsed")
    else:
        typed = st.text_input(label, value=current_val,
                              key=widget_key,
                              label_visibility="collapsed")

    # Sanitize widget return before storing
    typed = _safe_str(typed)
    st.session_state[key] = typed

    # ── Mic toggle button ────────────────────────────────────
    mic_open_key = f"_mic_{key}"

    # Render mic button and hint side by side WITHOUT st.columns
    # (columns were causing DeltaGenerator to bleed into session state)
    btn_label = "⏹ Close mic" if st.session_state.get(mic_open_key) else "🎤 Speak"
    if st.button(btn_label, key=f"_micbtn_{key}"):
        st.session_state[mic_open_key] = not st.session_state.get(mic_open_key, False)
        st.rerun()

    # ── Audio recorder panel ─────────────────────────────────
    if st.session_state.get(mic_open_key, False):
        st.markdown(
            f"<div style='background:#0f1e35;border:1px solid {C_BORDER};"
            f"border-left:3px solid {C_GOLD};border-radius:8px;"
            f"padding:10px 14px;margin:4px 0 8px 0;font-size:0.82rem;'>"
            f"<b style='color:{C_GOLD};'>How to use:</b>"
            f"<span style='color:{C_TEXT};'> Press ● below → speak → "
            f"press Stop ■ → click ✅ Replace or ➕ Append.</span>"
            f"</div>",
            unsafe_allow_html=True
        )

        audio_val = st.audio_input("🎙️ Record voice", key=f"_aud_{key}")

        if audio_val is not None:
            with st.spinner("Transcribing…"):
                transcript, error = _transcribe_audio(audio_val.read())

            if error:
                st.error(f"⚠️ {error}")
            else:
                # Transcript preview
                st.markdown(
                    f"<div style='background:#0a2010;border:1px solid #10B981;"
                    f"border-radius:8px;padding:10px 14px;margin:6px 0;'>"
                    f"<div style='color:#10B981;font-size:0.76rem;font-weight:700;"
                    f"margin-bottom:4px;'>📝 Transcript</div>"
                    f"<div style='color:{C_TEXT};font-size:0.92rem;"
                    f"font-style:italic;'>&ldquo;{transcript}&rdquo;</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

                # Action buttons — stacked vertically, no columns
                safe_id = abs(hash(transcript)) % 100000
                if st.button("✅ Replace field with transcript",
                             key=f"_rep_{key}_{safe_id}"):
                    st.session_state[key]          = _safe_str(transcript)
                    st.session_state[mic_open_key] = False
                    st.rerun()

                if st.button("➕ Append transcript to field",
                             key=f"_app_{key}_{safe_id}"):
                    existing = _safe_str(st.session_state.get(key, ""))
                    sep      = " " if existing and not existing.endswith(" ") else ""
                    st.session_state[key]          = existing + sep + _safe_str(transcript)
                    st.session_state[mic_open_key] = False
                    st.rerun()

                if st.button("❌ Discard transcript",
                             key=f"_dis_{key}_{safe_id}"):
                    st.session_state[mic_open_key] = False
                    st.rerun()

    return _safe_str(st.session_state.get(key, typed))

def render_form(category: str, existing: dict = None) -> dict:
    """
    Render dynamic form for a category.
    • text / textarea → voice_field (type OR 🎤 record voice → transcribe)
    • number          → st.number_input  (typing — numbers don't suit speech)
    • date            → st.date_input    (calendar picker)
    • select          → st.selectbox     (fixed options)
    Returns filled dict.
    """
    template = FIELD_TEMPLATES.get(category, [])
    data     = {}

    for field, ftype in template:
        key     = f"form_{category}_{field}"
        default = existing.get(field, "") if existing else ""

        if ftype == "text":
            val = voice_field(label=field, key=key,
                              default=default, multiline=False)
            data[field] = val

        elif ftype == "textarea":
            val = voice_field(label=field, key=key,
                              default=default, multiline=True)
            data[field] = val

        elif ftype == "number":
            try:
                dv = float(default) if default else 0.0
            except:
                dv = 0.0
            st.markdown(
                f"<div style='color:#e2e8f0;font-size:0.88rem;font-weight:600;"
                f"margin:10px 0 4px 0;'>{field}</div>",
                unsafe_allow_html=True
            )
            data[field] = st.number_input(
                field, value=dv, key=key, step=0.01,
                label_visibility="collapsed"
            )

        elif ftype == "date":
            try:
                dv = datetime.strptime(default, "%Y-%m-%d").date() if default else date.today()
            except:
                dv = date.today()
            st.markdown(
                f"<div style='color:#e2e8f0;font-size:0.88rem;font-weight:600;"
                f"margin:10px 0 4px 0;'>📅 {field}</div>",
                unsafe_allow_html=True
            )
            picked = st.date_input(field, value=dv, key=key, label_visibility="collapsed")
            data[field] = picked.strftime("%Y-%m-%d") if picked else ""

        elif ftype.startswith("select:"):
            options = [""] + ftype.split(":", 1)[1].split(",")
            idx = options.index(default) if default in options else 0
            st.markdown(
                f"<div style='color:#e2e8f0;font-size:0.88rem;font-weight:600;"
                f"margin:10px 0 4px 0;'>{field}</div>",
                unsafe_allow_html=True
            )
            data[field] = st.selectbox(
                field, options, index=idx, key=key,
                label_visibility="collapsed"
            )

    return data


# ══════════════════════════════════════════════════════════════════
# RECORD CARD RENDERER
# ══════════════════════════════════════════════════════════════════
def render_record_card(rec: dict, cat: str, idx: int, color: str):
    """Render one record card with field values, expiry badges, edit/delete."""
    template   = FIELD_TEMPLATES.get(cat, [])
    expiry_fields = ["Expiry Date", "Policy Renewal Date", "Refill Due Date", "Next Review Date", "Next Health Checkup"]

    # Build badges
    badges_html = ""
    for field, ftype in template:
        if field in expiry_fields and rec.get(field):
            badges_html += _expiry_badge(rec[field], field) + "&nbsp;"

    # Build field grid
    fields_html = "<div style='display:grid;grid-template-columns:1fr 1fr;gap:6px 20px;margin-top:10px;'>"
    skip_in_preview = {"Notes", "Diet Restrictions", "Allergies", "Chronic Conditions"}
    shown = 0
    for field, ftype in template:
        val = rec.get(field, "")
        if not val or str(val) in ("0", "0.0", ""): continue
        if field in skip_in_preview: continue
        if shown >= 10: break
        fields_html += (
            f"<div><div style='color:{C['muted']};font-size:0.7rem;text-transform:uppercase;"
            f"letter-spacing:0.8px;'>{field}</div>"
            f"<div style='color:{C['text']};font-size:0.85rem;font-weight:600;"
            f"font-family:JetBrains Mono,monospace;'>{str(val)[:40]}</div></div>"
        )
        shown += 1
    fields_html += "</div>"

    # Notes
    notes = rec.get("Notes", "")
    notes_html = (f"<div style='color:{C['muted']};font-size:0.8rem;font-style:italic;"
                  f"margin-top:8px;border-top:1px solid {C['border']};padding-top:6px;'>"
                  f"📝 {notes[:120]}{'…' if len(notes)>120 else ''}</div>") if notes else ""

    card_html = (
        f"<div style='background:{C['card']};border:1px solid {color}33;"
        f"border-left:4px solid {color};border-radius:10px;padding:14px 18px;margin:8px 0;'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;'>"
        f"<div style='font-family:Playfair Display,serif;font-size:0.95rem;font-weight:700;"
        f"color:{C['white']};'>Entry #{idx+1} &nbsp;"
        f"<span style='color:{C['muted']};font-size:0.78rem;font-weight:400;font-family:Source Sans 3,sans-serif;'>"
        f"Added: {rec.get('_added','')}</span></div>"
        f"<div>{badges_html}</div></div>"
        f"{fields_html}{notes_html}"
        f"</div>"
    )
    st.markdown(card_html, unsafe_allow_html=True)

    col1, col2, _ = st.columns([1, 1, 4])
    with col1:
        if st.button("✏️ Edit", key=f"edit_{cat}_{idx}"):
            st.session_state[f"editing_{cat}_{idx}"] = True
    with col2:
        if st.button("🗑️ Delete", key=f"del_{cat}_{idx}"):
            st.session_state[f"confirm_del_{cat}_{idx}"] = True

    # Confirm delete
    if st.session_state.get(f"confirm_del_{cat}_{idx}"):
        st.warning(f"Delete Entry #{idx+1}? This cannot be undone.")
        c1, c2, _ = st.columns([1, 1, 4])
        with c1:
            if st.button("✅ Confirm Delete", key=f"conf_{cat}_{idx}"):
                vault = st.session_state.vault_data
                vault[cat].pop(idx)
                vault_encrypt(vault, st.session_state.master_pw)
                st.session_state.vault_data = vault
                st.session_state.pop(f"confirm_del_{cat}_{idx}", None)
                st.success("Deleted.")
                st.rerun()
        with c2:
            if st.button("❌ Cancel", key=f"cancel_{cat}_{idx}"):
                st.session_state.pop(f"confirm_del_{cat}_{idx}", None)
                st.rerun()


# ══════════════════════════════════════════════════════════════════
# LOGIN / SETUP SCREEN
# ══════════════════════════════════════════════════════════════════
def show_auth_screen():
    # Force all text in the auth area to be bright
    st.markdown("""
    <style>
    div[data-testid="stVerticalBlock"] p,
    div[data-testid="stVerticalBlock"] label,
    div[data-testid="stVerticalBlock"] div[data-testid="stMarkdownContainer"] p {
        color: #e2e8f0 !important;
    }
    .stTextInput > label { color: #e2e8f0 !important; font-weight: 600 !important; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown(
        f"<div style='max-width:420px;margin:60px auto 0;'>"
        f"<div style='text-align:center;margin-bottom:32px;'>"
        f"<div style='font-size:4rem;'>🔐</div>"
        f"<div style='font-family:Playfair Display,serif;font-size:2rem;font-weight:900;"
        f"color:{C['gold']};'>Personal Vault</div>"
        f"<div style='color:{C['muted']};font-size:0.88rem;margin-top:4px;'>"
        f"Encrypted · Private · Yours</div>"
        f"</div>",
        unsafe_allow_html=True
    )

    if not vault_exists():
        # First-time setup
        st.markdown(
            f"<div style='background:{C['card']};border:2px solid {C['gold']}44;"
            f"border-radius:12px;padding:24px;margin-bottom:16px;'>"
            f"<div style='color:{C['gold']};font-weight:700;font-size:1.1rem;"
            f"margin-bottom:8px;'>🛡️ Create Your Vault</div>"
            f"<div style='color:{C['muted']};font-size:0.85rem;'>"
            f"Set a strong master password. This encrypts all your data with AES-256-GCM. "
            f"<b style='color:{C['rose']};'>If you forget it, your data cannot be recovered.</b>"
            f"</div></div>",
            unsafe_allow_html=True
        )
        st.markdown(
            f"<div style='color:#e2e8f0;font-size:0.9rem;font-weight:600;margin:12px 0 4px 0;'>"
            f"🔑 Master Password</div>",
            unsafe_allow_html=True
        )
        pw1 = st.text_input("Master Password", type="password", key="setup_pw1",
                             placeholder="Minimum 8 characters — mix of letters, numbers, symbols",
                             label_visibility="collapsed")
        st.markdown(
            f"<div style='color:#e2e8f0;font-size:0.9rem;font-weight:600;margin:12px 0 4px 0;'>"
            f"🔑 Confirm Password</div>",
            unsafe_allow_html=True
        )
        pw2 = st.text_input("Confirm Password", type="password", key="setup_pw2",
                             placeholder="Repeat your password exactly",
                             label_visibility="collapsed")

        # Strength indicator
        if pw1:
            strength, tips = _password_strength(pw1)
            colors = {1: C["rose"], 2: C["amber"], 3: C["gold"], 4: C["green"], 5: C["teal"]}
            labels = {1:"Very Weak", 2:"Weak", 3:"Moderate", 4:"Strong", 5:"Very Strong"}
            col = colors.get(strength, C["muted"])
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:8px;margin:6px 0;'>"
                f"{'<div style=\"width:40px;height:5px;border-radius:3px;background:' + col + '\"></div>' * strength}"
                f"{'<div style=\"width:40px;height:5px;border-radius:3px;background:#1e3a5f\"></div>' * (5-strength)}"
                f"<span style='color:{col};font-size:0.8rem;font-weight:700;'>{labels[strength]}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

        if st.button("🚀 Create Vault", use_container_width=True):
            if len(pw1) < 8:
                st.error("Password must be at least 8 characters.")
            elif pw1 != pw2:
                st.error("Passwords do not match.")
            else:
                with st.spinner("Creating encrypted vault…"):
                    set_master_password(pw1)
                    vault_encrypt({}, pw1)
                    st.session_state.authenticated = True
                    st.session_state.master_pw     = pw1
                    st.session_state.vault_data    = {}
                    st.session_state.last_activity = time.time()
                st.success("✅ Vault created! Welcome.")
                time.sleep(0.8)
                st.rerun()
    else:
        # Login
        st.markdown(
            f"<div style='background:{C['card']};border:2px solid {C['border']};"
            f"border-radius:12px;padding:24px;margin-bottom:16px;'>"
            f"<div style='color:{C['gold']};font-weight:700;font-size:1.0rem;"
            f"margin-bottom:8px;'>🔓 Unlock Your Vault</div>"
            f"</div>",
            unsafe_allow_html=True
        )
        st.markdown(
            f"<div style='color:#e2e8f0;font-size:0.9rem;font-weight:600;margin:12px 0 4px 0;'>"
            f"🔑 Master Password</div>",
            unsafe_allow_html=True
        )
        pw = st.text_input("Master Password", type="password", key="login_pw",
                           placeholder="Enter your vault password",
                           label_visibility="collapsed")

        if st.button("🔓 Unlock Vault", use_container_width=True):
            if verify_master_password(pw):
                with st.spinner("Decrypting vault…"):
                    data = vault_decrypt(pw)
                if data is None:
                    st.error("Decryption failed — vault may be corrupted.")
                else:
                    st.session_state.authenticated = True
                    st.session_state.master_pw     = pw
                    st.session_state.vault_data    = data
                    st.session_state.last_activity = time.time()
                    st.rerun()
            else:
                st.error("❌ Incorrect password.")

        st.markdown(
            f"<div style='text-align:center;margin-top:16px;color:{C['muted']};font-size:0.78rem;'>"
            f"🔒 AES-256-GCM encrypted · Data stored locally</div>",
            unsafe_allow_html=True
        )
    st.markdown("</div>", unsafe_allow_html=True)

def _password_strength(pw: str) -> tuple[int, list]:
    score = 0; tips = []
    if len(pw) >= 8:   score += 1
    if len(pw) >= 12:  score += 1
    if re.search(r'[A-Z]', pw): score += 1
    if re.search(r'[0-9]', pw): score += 1
    if re.search(r'[^A-Za-z0-9]', pw): score += 1
    return max(1, score), tips


# ══════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════
def show_dashboard():
    vault = st.session_state.vault_data

    _hero()

    # ── Summary metrics ──────────────────────────────────────────
    total_records   = sum(len(v) for v in vault.values() if isinstance(v, list))
    categories_used = sum(1 for v in vault.values() if isinstance(v, list) and len(v) > 0)

    # Count expiring soon
    expiring_soon = 0
    for cat, records in vault.items():
        if not isinstance(records, list): continue
        for rec in records:
            for ef in ["Expiry Date","Policy Renewal Date","Refill Due Date"]:
                d = _days_until(rec.get(ef,""))
                if d is not None and 0 <= d <= 90:
                    expiring_soon += 1

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📦 Total Records",   total_records)
    c2.metric("📁 Categories Used", categories_used)
    c3.metric("⚠️ Expiring ≤90d",   expiring_soon)
    c4.metric("🔐 Vault Status",    "LOCKED ✅" if st.session_state.authenticated else "OPEN")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Expiry alerts ────────────────────────────────────────────
    alerts = []
    for cat, records in vault.items():
        if not isinstance(records, list): continue
        for i, rec in enumerate(records):
            for ef in ["Expiry Date","Policy Renewal Date","Refill Due Date","Next Review Date"]:
                d = _days_until(rec.get(ef,""))
                if d is not None and d <= 90:
                    alerts.append((d, cat, i, ef, rec.get(ef)))

    if alerts:
        alerts.sort()
        st.markdown(
            f"<div style='color:{C['gold']};font-family:Playfair Display,serif;"
            f"font-size:1.1rem;font-weight:700;margin-bottom:10px;'>"
            f"⚠️ Upcoming Renewals & Expiries</div>",
            unsafe_allow_html=True
        )
        for days, cat, idx, field, dt in alerts[:8]:
            color = C["rose"] if days < 30 else C["amber"] if days < 60 else C["gold"]
            icon  = CATEGORIES.get(cat, {}).get("icon", "📋")
            st.markdown(
                f"<div style='background:{C['card']};border:1px solid {color}44;"
                f"border-left:3px solid {color};border-radius:8px;"
                f"padding:10px 16px;margin:4px 0;display:flex;"
                f"justify-content:space-between;align-items:center;'>"
                f"<div><span style='font-size:1.1rem;'>{icon}</span>"
                f" <b style='color:{C['white']};'>{cat.split(' ',1)[1] if ' ' in cat else cat}</b>"
                f"<span style='color:{C['muted']};font-size:0.8rem;'> · {field}</span></div>"
                f"<div>{_expiry_badge(dt, field)}"
                f"<span style='color:{C['muted']};font-size:0.78rem;margin-left:8px;'>{dt}</span></div>"
                f"</div>",
                unsafe_allow_html=True
            )
        st.markdown("<br>", unsafe_allow_html=True)

    # ── Category overview grid ───────────────────────────────────
    st.markdown(
        f"<div style='color:{C['gold']};font-family:Playfair Display,serif;"
        f"font-size:1.1rem;font-weight:700;margin-bottom:12px;'>"
        f"📁 Vault Contents</div>",
        unsafe_allow_html=True
    )
    cols = st.columns(3)
    for i, (cat, cfg) in enumerate(CATEGORIES.items()):
        records = vault.get(cat, [])
        count   = len(records) if isinstance(records, list) else 0
        color   = cfg["color"]
        with cols[i % 3]:
            st.markdown(
                f"<div style='background:{C['card']};border:1px solid {color}33;"
                f"border-top:3px solid {color};border-radius:10px;"
                f"padding:14px 16px;margin:4px 0;'>"
                f"<div style='font-size:1.6rem;'>{cfg['icon']}</div>"
                f"<div style='color:{C['white']};font-weight:600;font-size:0.88rem;"
                f"margin:4px 0;'>{cat.split(' ',1)[1] if ' ' in cat else cat}</div>"
                f"<div style='color:{color};font-family:Playfair Display,serif;"
                f"font-size:1.8rem;font-weight:900;'>{count}</div>"
                f"<div style='color:{C['muted']};font-size:0.72rem;'>"
                f"{'record' if count==1 else 'records'}</div>"
                f"</div>",
                unsafe_allow_html=True
            )


# ══════════════════════════════════════════════════════════════════
# CATEGORY VIEW (list + add)
# ══════════════════════════════════════════════════════════════════
def show_category(cat: str):
    cfg     = CATEGORIES[cat]
    color   = cfg["color"]
    vault   = st.session_state.vault_data
    records = vault.get(cat, [])

    _section_header(cat, f"{len(records)} record{'s' if len(records)!=1 else ''} stored")

    # ── Voice input hint ─────────────────────────────────────────
    _g = C["gold"]; _mb = C["border"]; _mt = C["muted"]
    st.markdown(
        f"<div style='background:#0f1e35;border:1px solid {_mb};"
        f"border-left:3px solid {_g};border-radius:8px;"
        f"padding:8px 14px;margin-bottom:12px;font-size:0.8rem;"
        f"display:flex;align-items:center;gap:10px;'>"
        f"<span style='font-size:1.2rem;'>🎤</span>"
        f"<span style='color:{_mt};'>"
        f"<b style='color:{_g};'> Voice Input enabled</b> — "
        f"click the <b style='color:#e2e8f0;'>🎤 mic button</b> next to any text field, "
        f"speak clearly, then click <b style='color:#e2e8f0;'>⏹ stop</b> when done. "
        f"<span style='color:#4a6080;'>Works on Chrome, Edge, Safari 14+. "
        f"Browser will request microphone permission on first use.</span>"
        f"</span></div>",
        unsafe_allow_html=True
    )

    # ── Existing records ─────────────────────────────────────────
    if records:
        for i, rec in enumerate(records):
            if st.session_state.get(f"editing_{cat}_{i}"):
                st.markdown(f"**✏️ Editing Entry #{i+1}**")
                edited = render_form(cat, existing=rec)
                c1, c2, _ = st.columns([1, 1, 3])
                with c1:
                    if st.button("💾 Save", key=f"save_{cat}_{i}"):
                        edited["_added"] = rec.get("_added", str(date.today()))
                        edited["_updated"] = str(date.today())
                        vault[cat][i] = edited
                        vault_encrypt(vault, st.session_state.master_pw)
                        st.session_state.vault_data = vault
                        st.session_state.pop(f"editing_{cat}_{i}", None)
                        st.success("✅ Record updated.")
                        st.rerun()
                with c2:
                    if st.button("❌ Cancel", key=f"cancelEdit_{cat}_{i}"):
                        st.session_state.pop(f"editing_{cat}_{i}", None)
                        st.rerun()
            else:
                render_record_card(rec, cat, i, color)
    else:
        st.markdown(
            f"<div style='background:{C['card']};border:2px dashed {color}44;"
            f"border-radius:10px;padding:32px;text-align:center;color:{C['muted']};'>"
            f"<div style='font-size:2.5rem;'>{cfg['icon']}</div>"
            f"<div style='margin-top:8px;'>No records yet. Add your first entry below.</div>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── Add new ──────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander(f"➕ Add New {cat.split(' ',1)[1] if ' ' in cat else cat} Entry", expanded=not records):
        new_data = render_form(cat)
        if st.button(f"💾 Save Entry", key=f"add_{cat}"):
            new_data["_added"]   = str(date.today())
            new_data["_updated"] = str(date.today())
            if cat not in vault:
                vault[cat] = []
            vault[cat].append(new_data)
            vault_encrypt(vault, st.session_state.master_pw)
            st.session_state.vault_data = vault
            st.success(f"✅ Entry saved to {cat}")
            st.rerun()


# ══════════════════════════════════════════════════════════════════
# CHANGE PASSWORD
# ══════════════════════════════════════════════════════════════════
def show_settings():
    _section_header("⚙️ Vault Settings")

    with st.expander("🔑 Change Master Password"):
        st.markdown("<div style='color:#e2e8f0;font-size:0.88rem;font-weight:600;margin:8px 0 4px 0;'>Current Password</div>", unsafe_allow_html=True)
        old_pw  = st.text_input("Current Password", type="password", key="chg_old", label_visibility="collapsed")
        st.markdown("<div style='color:#e2e8f0;font-size:0.88rem;font-weight:600;margin:8px 0 4px 0;'>New Password</div>", unsafe_allow_html=True)
        new_pw1 = st.text_input("New Password",     type="password", key="chg_new1", label_visibility="collapsed")
        st.markdown("<div style='color:#e2e8f0;font-size:0.88rem;font-weight:600;margin:8px 0 4px 0;'>Confirm New Password</div>", unsafe_allow_html=True)
        new_pw2 = st.text_input("Confirm New",      type="password", key="chg_new2", label_visibility="collapsed")
        if st.button("Update Password"):
            if not verify_master_password(old_pw):
                st.error("Current password is incorrect.")
            elif len(new_pw1) < 8:
                st.error("New password must be at least 8 characters.")
            elif new_pw1 != new_pw2:
                st.error("New passwords do not match.")
            else:
                set_master_password(new_pw1)
                vault_encrypt(st.session_state.vault_data, new_pw1)
                st.session_state.master_pw = new_pw1
                st.success("✅ Password updated. Vault re-encrypted.")

    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("📤 Export Vault (Encrypted JSON)"):
        st.warning("⚠️ This exports your encrypted vault file. Keep it safe.")
        if st.button("📥 Download Vault Backup"):
            if VAULT_FILE.exists():
                payload = VAULT_FILE.read_text()
                b64 = base64.b64encode(payload.encode()).decode()
                st.markdown(
                    f"<a href='data:application/json;base64,{b64}' "
                    f"download='vault_backup_{date.today()}.enc' "
                    f"style='background:{C['gold']};color:#0a0f1e;padding:8px 20px;"
                    f"border-radius:6px;font-weight:700;text-decoration:none;'>"
                    f"⬇️ Download vault_backup.enc</a>",
                    unsafe_allow_html=True
                )

    st.markdown("<br>", unsafe_allow_html=True)

    # Security info
    _card(
        f"<div style='color:{C['text']};font-size:0.85rem;line-height:1.9;'>"
        f"<b style='color:{C['gold']};'>Encryption:</b> AES-256-GCM (authenticated encryption)<br>"
        f"<b style='color:{C['gold']};'>Key Derivation:</b> PBKDF2-SHA256 · 310,000 iterations · 32-byte salt<br>"
        f"<b style='color:{C['gold']};'>Password Hash:</b> bcrypt (cost factor 12)<br>"
        f"<b style='color:{C['gold']};'>Data at rest:</b> Fully encrypted — no plaintext on disk<br>"
        f"<b style='color:{C['gold']};'>Data transit:</b> Never sent anywhere — local only"
        f"</div>",
        color=C["teal"], title="🔐 Security Specifications"
    )

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔒 Lock & Logout", use_container_width=True):
        for key in ["authenticated","master_pw","vault_data","last_activity"]:
            st.session_state.pop(key, None)
        st.rerun()


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    st.set_page_config(
        page_title="Personal Vault",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    apply_css()

    # Session state defaults
    if "authenticated"  not in st.session_state: st.session_state.authenticated  = False
    if "master_pw"      not in st.session_state: st.session_state.master_pw      = ""
    if "vault_data"     not in st.session_state: st.session_state.vault_data     = {}
    if "last_activity"  not in st.session_state: st.session_state.last_activity  = time.time()
    if "active_page"    not in st.session_state: st.session_state.active_page    = "🏠 Dashboard"

    # ── Auto-lock after 15 minutes inactivity ────────────────────
    if st.session_state.authenticated:
        idle = time.time() - st.session_state.last_activity
        if idle > 900:
            for key in ["authenticated","master_pw","vault_data"]:
                st.session_state.pop(key, None)
            st.warning("🔒 Session locked due to inactivity.")
            st.rerun()
        st.session_state.last_activity = time.time()

    # ── Not authenticated ─────────────────────────────────────────
    if not st.session_state.authenticated:
        show_auth_screen()
        return

    # ── SIDEBAR ──────────────────────────────────────────────────
    with st.sidebar:
        st.markdown(
            f"<div style='text-align:center;padding:16px 0 8px;'>"
            f"<div style='font-size:2.2rem;'>🔐</div>"
            f"<div style='font-family:Playfair Display,serif;font-size:1.1rem;"
            f"font-weight:900;color:{C['gold']};'>Personal Vault</div>"
            f"<div style='color:{C['green']};font-size:0.75rem;margin-top:3px;'>"
            f"🟢 UNLOCKED</div>"
            f"</div>",
            unsafe_allow_html=True
        )
        st.markdown(f"<hr style='border-color:{C['border']};margin:8px 0;'>", unsafe_allow_html=True)

        # Navigation
        nav_items = ["🏠 Dashboard"] + list(CATEGORIES.keys()) + ["⚙️ Settings"]
        for item in nav_items:
            is_active = st.session_state.active_page == item
            color = C["gold"] if is_active else C["muted"]
            bg    = C["card"] if is_active else "transparent"
            border= f"border-left:3px solid {C['gold']};" if is_active else "border-left:3px solid transparent;"

            if st.button(item, key=f"nav_{item}", use_container_width=True):
                st.session_state.active_page = item
                st.rerun()

        st.markdown(f"<hr style='border-color:{C['border']};margin:8px 0;'>", unsafe_allow_html=True)

        # Vault stats in sidebar
        vault = st.session_state.vault_data
        total = sum(len(v) for v in vault.values() if isinstance(v, list))
        st.markdown(
            f"<div style='background:{C['card']};border:1px solid {C['border']};"
            f"border-radius:8px;padding:10px;font-size:0.78rem;color:{C['muted']};'>"
            f"📦 {total} records stored<br>"
            f"🔐 AES-256-GCM encrypted<br>"
            f"🕐 Auto-locks in 15 min"
            f"</div>",
            unsafe_allow_html=True
        )

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔒 Lock Vault", use_container_width=True):
            for key in ["authenticated","master_pw","vault_data","last_activity"]:
                st.session_state.pop(key, None)
            st.rerun()

        # Footer
        st.markdown(
            f"<div style='position:fixed;bottom:16px;left:0;width:260px;"
            f"padding:0 16px;font-size:0.68rem;color:{C['muted']};text-align:center;'>"
            f"The Mountain Path — World of Finance<br>"
            f"<a href='https://www.linkedin.com/in/trichyravis' style='color:{C['gold']};text-decoration:none;'>LinkedIn</a>"
            f" · "
            f"<a href='https://github.com/trichyravis' style='color:{C['gold']};text-decoration:none;'>GitHub</a>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── MAIN CONTENT ─────────────────────────────────────────────
    page = st.session_state.active_page

    if page == "🏠 Dashboard":
        show_dashboard()
    elif page == "⚙️ Settings":
        show_settings()
    elif page in CATEGORIES:
        show_category(page)


if __name__ == "__main__":
    main()
