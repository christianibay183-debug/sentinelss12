from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify, send_from_directory, abort
from functools import wraps
from datetime import datetime
import os
import json
import cv2
import glob
import logging
import time
import requests as req
import secrets

# Security and Database dependencies
from dotenv import load_dotenv
import psycopg2
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__, template_folder="Frontend/html", static_folder="Frontend", static_url_path="")
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-for-local-dev")

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") != "development",
    SESSION_COOKIE_HTTPONLY=True
)

CCTV_FOLDER = os.path.join(os.path.dirname(__file__), "cctv_footage")
LOG_FILE    = os.path.join(os.path.dirname(__file__), "logs", "access.log")

os.makedirs(CCTV_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ─── In-memory stream URL override ───────────────────────────────────────────# 
# TUNNEL_URL must be the FULL MJPEG stream URL, e.g.:
#   https://your-tunnel.trycloudflare.com/stream
# Admin can update it at runtime via POST /api/stream-config without redeploying.
# Falls back to the old NGROK_URL var (also expected to be the full stream URL).

_tunnel_url_override: str | None = None

def get_tunnel_url() -> str:
    """Return the full stream URL (no trailing slash). Never appends /stream."""
    if _tunnel_url_override:
        return _tunnel_url_override.rstrip("/")
    return (os.getenv("TUNNEL_URL") or os.getenv("NGROK_URL") or "").rstrip("/")

# ─────────────────────────────────────────────────────────────────────────────

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return psycopg2.connect(db_url)
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT", 5432)
    )

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("cctv")

failed_attempts = {}

# ─── Security Configuration & IP Blacklist File Tracking ─────────────────────
BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), "blacklist.json")

def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "r") as f:
                content = f.read().strip()
                if not content:
                    return set()
                return set(json.loads(content))
        except Exception:
            return set()
    return set()

def save_blacklist(blacklist):
    try:
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(list(blacklist), f)
    except Exception as e:
        logger.error(f"Error saving blacklist file: {e}")

blacklisted_ips = load_blacklist()

def write_log(event: str, user: str = "anonymous", ip: str = ""):
    msg = f"USER={user} | IP={ip} | {event}"
    logger.info(msg)


### GLOBAL SECURITY INTERCEPTOR (HOISTED GATEKEEPER) ###
@app.before_request
def block_blacklisted_ips():
    # Detect behind tunnels/proxies accurately
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip in blacklisted_ips:
        write_log("BLACKLISTED_IP_BLOCKED", "unauthorized", ip)
        return jsonify({"error": "Access Denied: Your IP address has been permanently blocked."}), 403



def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        if session["user"] != "admin":
            return jsonify({"error": "Admin only"}), 403
        return f(*args, **kwargs)
    return decorated

CAMERAS = {}
caps    = {}

def get_camera_config():
    cfg_path = os.path.join(os.path.dirname(__file__), "cameras.json")
    if os.path.exists(cfg_path):
        with open(cfg_path) as f:
            return json.load(f)
    return []

for cam in get_camera_config():
    CAMERAS[cam["id"]] = cam["source"]

def generate_frames(cam_id: int):
    src = CAMERAS.get(cam_id, cam_id)
    if cam_id not in caps or not caps[cam_id].isOpened():
        caps[cam_id] = cv2.VideoCapture(src)
    cap = caps[cam_id]
    while True:
        success, frame = cap.read()
        if not success:
            placeholder = cv2.imencode(".jpg", cv2.UMat(480, 640, cv2.CV_8UC3).get())[1]
            yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + placeholder.tobytes() + b"\r\n")
            time.sleep(1)
            cap = cv2.VideoCapture(src)
            caps[cam_id] = cap
            continue
        _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
        yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + buf.tobytes() + b"\r\n")


@app.before_request
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

def validate_csrf():
    """Call this on every state-changing request."""
    token = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
    )
    if not token or token != session.get("csrf_token"):
        abort(403, "CSRF validation failed")

@app.route("/api/transfer", methods=["POST"])
def transfer():
    validate_csrf()
    return jsonify({"status": "ok"})

@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    """Endpoint for JS to fetch the token."""
    return jsonify({"csrf_token": session["csrf_token"]})

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    error = None
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    current_time = time.time()

    # Pre-render logic: Keep showing the lock status countdown if user simply refreshes the browser
    if ip in failed_attempts and current_time < failed_attempts[ip]["locked_until"]:
        remaining = int(failed_attempts[ip]["locked_until"] - current_time)
        return render_template("login.html", locked=True, remaining=remaining)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if ip not in failed_attempts:
            failed_attempts[ip] = {"count": 0, "locked_until": 0}

        user_record = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT password_hash FROM user_credentials WHERE username = %s;", (username,))
            user_record = cur.fetchone()
            cur.close()
            conn.close()
        except Exception as e:
            logger.error(f"Database error during login: {e}")
            error = "Database connection issue."

        if user_record and check_password_hash(user_record[0], password):
            failed_attempts[ip]["count"] = 0
            session["user"] = username
            write_log("LOGIN_SUCCESS", username, ip)
            return redirect(url_for("dashboard"))
        else:
            failed_attempts[ip]["count"] += 1
            write_log("LOGIN_FAILED", username, ip)
            error = "Invalid username or password."

            # RULE 2: 5 cumulative failed attempts = Permanent IP Lockout/Ban
            if failed_attempts[ip]["count"] >= 5:
                blacklisted_ips.add(ip)
                save_blacklist(blacklisted_ips)
                write_log("IP_BLACKLISTED", username, ip)
                
                # Drop tracking data since they are managed globally by @app.before_request now
                failed_attempts.pop(ip, None)
                return render_template("login.html", error="Your IP has been permanently blocked.")

            # RULE 1: 3 failed attempts = 60-second cooldown penalty with timer
            elif failed_attempts[ip]["count"] >= 3:
                failed_attempts[ip]["locked_until"] = time.time() + 60
                write_log("RATE_LIMIT_TRIGGERED", username, ip)
                return render_template("login.html", locked=True, remaining=60)

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    user = session.pop("user", "unknown")
    write_log("LOGOUT", user, request.headers.get("X-Forwarded-For", request.remote_addr))
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    cameras = get_camera_config()
    write_log("VIEW_DASHBOARD", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return render_template("dashboard.html", cameras=cameras, user=session["user"])

@app.route("/stream/<int:cam_id>")
def stream(cam_id):
    response = Response(
        generate_frames(cam_id),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

@app.route("/footage")
@login_required
def footage():
    files = sorted(glob.glob(os.path.join(CCTV_FOLDER, "**", "*"), recursive=True))
    media = []
    for f in files:
        if os.path.isfile(f):
            rel   = os.path.relpath(f, CCTV_FOLDER)
            size  = os.path.getsize(f)
            mtime = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%Y-%m-%d %H:%M:%S")
            ext   = os.path.splitext(f)[1].lower()
            media.append({"name": rel, "size": size, "modified": mtime, "ext": ext})
    write_log("VIEW_FOOTAGE", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return render_template("footage.html", media=media, user=session["user"])

@app.route("/footage/file/<path:filename>")
@login_required
def serve_footage(filename):
    write_log(f"DOWNLOAD_FOOTAGE file={filename}", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return send_from_directory(CCTV_FOLDER, filename)

@app.route("/logs")
@login_required
def logs():
    lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            lines = f.readlines()[-200:]
    lines = [l.strip() for l in reversed(lines)]
    write_log("VIEW_LOGS", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return render_template("logs.html", lines=lines, user=session["user"])

@app.route("/restricteds")
@admin_required
def admin_panel():
    write_log("VIEW_ADMIN", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return render_template("restricteds.html", blacklisted_ips=sorted(blacklisted_ips), user=session["user"])

@app.route("/admin/add_ip", methods=["POST"])
@admin_required
def add_blacklisted_ip():
    validate_csrf()
    ip = request.form.get("ip", "").strip()
    if not ip:
        return redirect(url_for("admin_panel"))
    blacklisted_ips.add(ip)
    failed_attempts.pop(ip, None)
    save_blacklist(blacklisted_ips)
    write_log(f"MANUAL_IP_BLACKLIST ip={ip}", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return redirect(url_for("admin_panel"))

@app.route("/admin/remove_ip", methods=["POST"])
@admin_required
def remove_blacklisted_ip():
    validate_csrf()
    ip = request.form.get("ip", "").strip()
    if not ip:
        return redirect(url_for("admin_panel"))
    blacklisted_ips.discard(ip)
    failed_attempts.pop(ip, None)
    save_blacklist(blacklisted_ips)
    write_log(f"MANUAL_IP_UNBLOCKED ip={ip}", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return redirect(url_for("admin_panel"))

@app.route("/api/cameras")
@login_required
def api_cameras():
    return jsonify(get_camera_config())

@app.route("/api/logs")
@login_required
def api_logs():
    lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            lines = [l.strip() for l in f.readlines()[-100:]]
    return jsonify({"logs": list(reversed(lines))})

# ─── Stream config API ────────────────────────────────────────────────────────

@app.route("/api/stream-config", methods=["GET"])
@login_required
def get_stream_config():
    tunnel = get_tunnel_url()
    return jsonify({
        "tunnel_url": tunnel,
        "proxy_endpoint": "/proxy/stream",
        "configured": bool(tunnel),
        "is_admin": session.get("user") == "admin",
    })

@app.route("/api/stream-config", methods=["POST"])
@admin_required
def set_stream_config():
    global _tunnel_url_override
    data = request.get_json(silent=True) or {}
    url  = (data.get("tunnel_url") or "").strip().rstrip("/")

    if not url:
        return jsonify({"error": "tunnel_url is required"}), 400

    if not url.startswith("http"):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    _tunnel_url_override = url
    write_log(f"STREAM_CONFIG_UPDATED url={url}", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return jsonify({"ok": True, "tunnel_url": url})

@app.route("/api/stream-health", methods=["GET"])
@login_required
def stream_health():
    tunnel = get_tunnel_url()
    if not tunnel:
        return jsonify({"ok": False, "reason": "not_configured"}), 200

    stream_url = tunnel
    try:
        r = req.get(
            stream_url,
            headers={
                "cf-access-skip-interstitial": "true",
                "User-Agent": "python-requests/2.31.0",
            },
            stream=True,
            timeout=6,
        )
        chunk = next(r.iter_content(512), None)
        r.close()
        if r.status_code == 200 and chunk:
            return jsonify({"ok": True, "status_code": r.status_code})
        return jsonify({"ok": False, "reason": f"http_{r.status_code}"}), 200
    except req.exceptions.Timeout:
        return jsonify({"ok": False, "reason": "timeout"}), 200
    except Exception as e:
        return jsonify({"ok": False, "reason": str(e)}), 200

# ─── Proxy ────────────────────────────────────────────────────────────────────

@app.route("/proxy/stream")
@login_required
def proxy_stream():
    tunnel = get_tunnel_url()
    if not tunnel:
        return jsonify({"error": "Tunnel URL not configured. Set TUNNEL_URL in Railway env vars or use Settings."}), 503

    url = tunnel
    try:
        r = req.get(
            url,
            headers={
                "cf-access-skip-interstitial": "true",
                "ngrok-skip-browser-warning": "true",
                "User-Agent": "python-requests/2.31.0",
            },
            stream=True,
            timeout=30,
        )
        return Response(
            r.iter_content(chunk_size=4096),
            status=r.status_code,
            content_type=r.headers.get("Content-Type", "multipart/x-mixed-replace; boundary=frame"),
        )
    except Exception as e:
        logger.error(f"Proxy stream error: {e}")
        return jsonify({"error": str(e)}), 502

@app.route("/proxy", defaults={"path": ""})
@app.route("/proxy/<path:path>", methods=["GET", "POST"])
def proxy(path):
    tunnel = get_tunnel_url()
    if not tunnel:
        return jsonify({"error": "TUNNEL_URL not set"}), 500
    url = f"{tunnel}/{path}"
    try:
        r = req.request(
            method=request.method,
            url=url,
            headers={
                **{k: v for k, v in request.headers if k != "Host"},
                "ngrok-skip-browser-warning": "true",
                "cf-access-skip-interstitial": "true",
                "User-Agent": "python-requests/2.31.0",
            },
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=True,
            stream=True,
            timeout=10,
        )
        return Response(r.iter_content(chunk_size=1024), status=r.status_code, content_type=r.headers.get("Content-Type"))
    except Exception as e:
        return jsonify({"error": str(e)}), 502

@app.route("/api/stream-url")
def stream_url():
    tunnel = get_tunnel_url()
    return jsonify({"url": f"{tunnel}/stream/0" if tunnel else ""})

# ─── Manual Administration Control ──────────────────────────────────────────
@app.route("/admin/blacklist/<ip>")
@admin_required
def manual_blacklist_ip(ip):
    """Allows administrators to explicitly add malicious IPs directly to storage."""
    blacklisted_ips.add(ip)
    save_blacklist(blacklisted_ips)
    write_log("MANUAL_IP_BLACKLIST", session["user"], request.headers.get("X-Forwarded-For", request.remote_addr))
    return jsonify({"success": True, "blacklisted_ip": ip})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)