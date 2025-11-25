from flask import Flask, request, jsonify, session
from flask_cors import CORS
from datetime import datetime, timedelta
from dotenv import load_dotenv
import uuid
import json
import os
import hashlib
import secrets
from pyngrok import ngrok

# Load environment variables
load_dotenv('/kaggle/input/dotenv-file/.env')

# Configuration from .env
LLM_SERVER_URL = os.getenv("LLM_SERVER_URL")
PASSKEY = os.getenv("PASSKEY")
TURN_LIMIT = 10
SECRET_KEY = os.getenv("SECRET_KEY")
frontend_url = os.getenv("FRONTEND_URL")
NGROK_TOKEN= os.getenv("NGROK_AUTH_TOKEN")

# ============================================
# CHAT MANAGER - With Authentication System (FIXED)
# ============================================


app = Flask(__name__)
CORS(app,
     supports_credentials=True,
     origins=[
         frontend_url
     ],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])




app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = True  # Set True for HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Data storage files - Create directory if it doesn't exist
DATA_DIR = "/kaggle/working/"
os.makedirs(DATA_DIR, exist_ok=True)

DATA_FILE = os.path.join(DATA_DIR, "chat_sessions.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# ============================================
# User Management
# ============================================

def load_users():
    """Load users from file"""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️ Users file corrupted, creating new one")
            return {}
        except Exception as e:
            print(f"⚠️ Error loading users: {e}")
            return {}
    return {}

def save_users(users):
    """Save users to file"""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        print(f"✅ Users saved to {USERS_FILE}")
    except Exception as e:
        print(f"⚠️ Error saving users: {e}")

def hash_password(password):
    """Hash password with SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, password, name, passkey):
    """Create new user account"""
    users = load_users()
    
    # Validate username
    if username in users:
        return False, "Username already exists"
    
    # Validate passkey
    if passkey != PASSKEY:
        return False, "Invalid system passkey"
    
    # Create new user
    users[username] = {
        "username": username,
        "password": hash_password(password),
        "name": name,
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "sessions": []  # List of session IDs belonging to this user
    }
    
    save_users(users)
    print(f"✅ User created: {username}")
    return True, "Account created successfully"

def verify_user(username, password, passkey):
    """Verify user credentials"""
    # Validate passkey first
    if passkey != PASSKEY:
        return False, "Invalid system passkey"
    
    users = load_users()
    
    # Check if user exists
    if username not in users:
        return False, "Username not found"
    
    # Verify password
    if users[username]["password"] != hash_password(password):
        return False, "Incorrect password"
    
    # Update last login
    users[username]["last_login"] = datetime.now().isoformat()
    save_users(users)
    
    print(f"✅ User verified: {username}")
    return True, "Login successful"

def get_user_info(username):
    """Get user information (without password)"""
    users = load_users()
    if username in users:
        user = users[username].copy()
        user.pop('password', None)  # Remove password from response
        return user
    return None

# ============================================
# Session Data Storage
# ============================================

chat_sessions = {}

def load_sessions():
    """Load sessions from file"""
    global chat_sessions
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                chat_sessions = json.load(f)
            print(f"✅ Loaded {len(chat_sessions)} sessions from disk")
        except json.JSONDecodeError:
            print(f"⚠️ Sessions file corrupted, starting fresh")
            chat_sessions = {}
        except Exception as e:
            print(f"⚠️ Error loading sessions: {e}")
            chat_sessions = {}
    else:
        chat_sessions = {}
        print("📝 No existing sessions file, starting fresh")

def save_sessions():
    """Save sessions to file"""
    try:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(chat_sessions, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Error saving sessions: {e}")

# Load sessions on startup
load_sessions()

# ============================================
# Session Management
# ============================================

def get_or_create_session(session_id, username, mode="model"):
    """Get existing session or create new one"""
    if session_id not in chat_sessions:
        chat_sessions[session_id] = {
            "id": session_id,
            "username": username,
            "title": "New Chat",
            "mode": mode,
            "messages": [],
            "turn_count": 0,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Add session to user's session list
        users = load_users()
        if username in users:
            if "sessions" not in users[username]:
                users[username]["sessions"] = []
            if session_id not in users[username]["sessions"]:
                users[username]["sessions"].append(session_id)
                save_users(users)
        
        save_sessions()
        print(f"✅ Created session {session_id} for user {username}")
    
    return chat_sessions[session_id]

def add_message(session_id, role, content):
    """Add message to session"""
    if session_id not in chat_sessions:
        print(f"⚠️ Session not found: {session_id}")
        return None
    
    message = {
        "id": str(uuid.uuid4()),
        "role": role,
        "content": content,
        "timestamp": datetime.now().isoformat()
    }
    
    chat_sessions[session_id]["messages"].append(message)
    chat_sessions[session_id]["updated_at"] = datetime.now().isoformat()
    
    # Increment turn count for user messages
    if role == "user":
        chat_sessions[session_id]["turn_count"] += 1
    
    # Update session title from first user message
    if chat_sessions[session_id]["title"] == "New Chat" and role == "user":
        title = content[:50] + ("..." if len(content) > 50 else "")
        chat_sessions[session_id]["title"] = title
    
    save_sessions()
    return message

def get_user_sessions(username):
    """Get all sessions for a user"""
    user_sessions = []
    for session_id, sess in chat_sessions.items():
        if sess.get("username") == username:
            user_sessions.append(sess)
    
    # Sort by most recently updated
    return sorted(user_sessions, key=lambda x: x.get("updated_at", ""), reverse=True)

def check_turn_limit(session_id):
    """Check if session reached turn limit"""
    if session_id not in chat_sessions:
        return False
    return chat_sessions[session_id]["turn_count"] >= TURN_LIMIT

# ============================================
# Authentication Endpoints
# ============================================
@app.route("/")
def home():
    return {"message": "Hello World!"}

@app.route("/auth/register", methods=["POST", "OPTIONS"])
def register():
    """Register new user"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")
        confirm_password = data.get("confirm_password", "")
        name = data.get("name", "").strip()
        passkey = data.get("passkey", "")
        
        print(f"📝 Registration attempt for username: {username}")
        
        # Validation
        if not all([username, password, confirm_password, name, passkey]):
            return jsonify({"error": "All fields are required"}), 400
        
        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters"}), 400
        
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        
        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400
        
        # Create user
        success, message = create_user(username, password, name, passkey)
        
        if success:
            return jsonify({"message": message}), 201
        else:
            return jsonify({"error": message}), 400
            
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route("/auth/login", methods=["POST", "OPTIONS"])
def login():
    """Login user"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")
        passkey = data.get("passkey", "")
        
        print(f"🔐 Login attempt for user: {username}")
        
        if not all([username, password, passkey]):
            return jsonify({"error": "All fields are required"}), 400
        
        # Verify credentials
        success, message = verify_user(username, password, passkey)
        
        if success:
            # Create session
            session['username'] = username
            session.permanent = True
            
            user_info = get_user_info(username)
            
            print(f"✅ User logged in: {username}")
            
            return jsonify({
                "message": message,
                "user": user_info,
                "llm_url": LLM_SERVER_URL
            }), 200
        else:
            print(f"❌ Login failed for {username}: {message}")
            return jsonify({"error": message}), 401
            
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@app.route("/auth/logout", methods=["POST", "OPTIONS"])
def logout():
    """Logout user"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    username = session.get('username', 'unknown')
    session.clear()
    print(f"👋 User logged out: {username}")
    return jsonify({"message": "Logged out successfully"}), 200

@app.route("/auth/check", methods=["GET", "OPTIONS"])
def check_auth():
    """Check if user is authenticated"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    username = session.get('username')
    
    if username:
        user_info = get_user_info(username)
        if user_info:
            return jsonify({
                "authenticated": True,
                "user": user_info,
                "llm_url": LLM_SERVER_URL
            }), 200
    
    return jsonify({"authenticated": False}), 200



def require_auth(f):
    """Decorator to require authentication"""
    def wrapper(*args, **kwargs):

        # ⭐ FIX: allow CORS preflight OPTIONS through
        if request.method == "OPTIONS":
            return jsonify({"status": "ok"}), 200

        username = session.get('username')
        
        if not username:
            print("❌ Unauthorized access attempt")
            return jsonify({"error": "Not authenticated"}), 401
        
        return f(*args, **kwargs)
    
    wrapper.__name__ = f.__name__
    return wrapper


@app.route("/sessions", methods=["GET", "OPTIONS"])
@require_auth
def get_sessions():
    """Get all chat sessions for current user"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    username = session['username']
    print(f"📋 Getting sessions for user: {username}")
    
    sessions_list = get_user_sessions(username)
    
    summary = []
    for sess in sessions_list:
        summary.append({
            "id": sess["id"],
            "title": sess["title"],
            "mode": sess.get("mode", "model"),
            "turn_count": sess["turn_count"],
            "message_count": len(sess["messages"]),
            "created_at": sess["created_at"],
            "updated_at": sess["updated_at"],
            "is_limit_reached": sess["turn_count"] >= TURN_LIMIT
        })
    
    print(f"✅ Returning {len(summary)} sessions")
    return jsonify({"sessions": summary}), 200

@app.route("/session/<session_id>", methods=["GET", "OPTIONS"])
@require_auth
def get_session(session_id):
    """Get specific session"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    username = session['username']
    
    if session_id not in chat_sessions:
        return jsonify({"error": "Session not found"}), 404
    
    if chat_sessions[session_id].get("username") != username:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify({"session": chat_sessions[session_id]}), 200

@app.route("/session/new", methods=["POST", "OPTIONS"])
@require_auth
def create_session():
    """Create new chat session"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    try:
        username = session['username']
        data = request.get_json() or {}
        mode = data.get("mode", "model")
        
        session_id = f"chat_{uuid.uuid4().hex[:12]}"
        sess = get_or_create_session(session_id, username, mode)
        
        print(f"✅ Created session {session_id} for user {username} with mode {mode}")
        
        return jsonify({
            "message": "Session created",
            "session_id": session_id,
            "session": sess
        }), 201
        
    except Exception as e:
        print(f"❌ Error creating session: {e}")
        return jsonify({"error": f"Failed to create session: {str(e)}"}), 500

@app.route("/session/<session_id>", methods=["DELETE", "OPTIONS"])
@require_auth
def delete_session(session_id):
    """Delete a session"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    username = session['username']
    
    if session_id not in chat_sessions:
        return jsonify({"message": "Session already deleted"}), 200
    
    if chat_sessions[session_id].get("username") != username:
        return jsonify({"error": "Unauthorized"}), 403
    
    # Delete session
    del chat_sessions[session_id]
    save_sessions()
    
    # Remove from user's session list
    users = load_users()
    if username in users and "sessions" in users[username]:
        if session_id in users[username]["sessions"]:
            users[username]["sessions"].remove(session_id)
            save_users(users)
    
    print(f"✅ Deleted session {session_id}")
    return jsonify({"message": "Session deleted"}), 200

@app.route("/message", methods=["POST", "OPTIONS"])
@require_auth
def add_message_endpoint():
    """Add message to session"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    try:
        username = session['username']
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        session_id = data.get("session_id")
        role = data.get("role")
        content = data.get("content")
        
        if not all([session_id, role, content]):
            return jsonify({"error": "Missing required fields"}), 400
        
        if session_id not in chat_sessions:
            return jsonify({"error": "Session not found"}), 404
        
        if chat_sessions[session_id].get("username") != username:
            return jsonify({"error": "Unauthorized"}), 403
        
        message = add_message(session_id, role, content)
        
        if message:
            return jsonify({"message": message}), 201
        else:
            return jsonify({"error": "Failed to add message"}), 500
            
    except Exception as e:
        print(f"❌ Error adding message: {e}")
        return jsonify({"error": f"Failed to add message: {str(e)}"}), 500

@app.route("/context/<session_id>", methods=["GET", "OPTIONS"])
@require_auth
def get_context(session_id):
    """Get conversation context for session"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    username = session['username']
    
    if session_id not in chat_sessions:
        return jsonify({"error": "Session not found"}), 404
    
    if chat_sessions[session_id].get("username") != username:
        return jsonify({"error": "Unauthorized"}), 403
    
    sess = chat_sessions[session_id]
    turn_count = sess["turn_count"]
    is_limit = turn_count >= TURN_LIMIT
    
    # Get recent messages for context
    messages = sess["messages"]
    turns_param = request.args.get("turns", 5)
    try:
        num_turns = int(turns_param)
    except:
        num_turns = 5
    
    recent_messages = messages[-(num_turns * 2):] if len(messages) > 0 else []
    context = "\n".join([f"{msg['role']}: {msg['content']}" for msg in recent_messages])
    
    return jsonify({
        "turn_count": turn_count,
        "is_limit_reached": is_limit,
        "turn_limit": TURN_LIMIT,
        "context": context
    }), 200

@app.route("/config", methods=["POST", "OPTIONS"])
def update_config():
    """Update configuration (for settings page)"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    try:
        data = request.get_json()
        # This is just for compatibility - actual config is in .env
        return jsonify({"message": "Config updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
from flask_cors import cross_origin

@app.route("/health", methods=["GET", "OPTIONS"])
@cross_origin(origins="*", supports_credentials=False)
def health():
    """Health check endpoint"""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    return jsonify({
        "status": "ok",
        "service": "Local Chat Manager with Auth",
        "total_users": len(load_users()),
        "total_sessions": len(chat_sessions),
        "llm_server": LLM_SERVER_URL if LLM_SERVER_URL else "Not configured",
        "turn_limit": TURN_LIMIT,
        "authenticated": 'username' in session
    }), 200

# ============================================
# Run Server
# ============================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("💬 Local Chat Manager Starting (With Authentication)...")
    print("="*60)
    print(f"📍 Running on: http://localhost:5002")
    print(f"🤖 LLM Server: {LLM_SERVER_URL if LLM_SERVER_URL else 'Not configured'}")
    print(f"💾 Data Directory: {DATA_DIR}")
    print(f"📄 Sessions File: {DATA_FILE}")
    print(f"👥 Users File: {USERS_FILE}")
    print(f"📊 Sessions Loaded: {len(chat_sessions)}")
    print(f"👥 Users Registered: {len(load_users())}")
    print(f"🔢 Turn Limit: {TURN_LIMIT}")
    print(f"🔐 Authentication: Enabled")
    print(f"🔑 System Passkey: {PASSKEY}")
    print("="*60 + "\n")
    
    # Run server
    app.run(host='0.0.0.0', port=5002, debug=True, use_reloader=False)

