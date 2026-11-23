#!/usr/bin/env python3
"""
leon.music — desktop tray app + streaming server
─────────────────────────────────────────────────
Install deps:
    pip install fastapi uvicorn mutagen pystray pillow --break-system-packages

Run directly:
    python leon_music.py

Build as single .exe (Windows):
    pyinstaller --onefile --windowed --name "leon.music" leon_music.py

Build as .app (macOS):
    pyinstaller --onefile --windowed --name "leon.music" leon_music.py
"""

import asyncio
import base64
import hashlib
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path
import socket
import ssl
from time import sleep, time as _now
from typing import Optional
from urllib.parse import urlparse, urljoin, quote

# ── Dependency check ──────────────────────────────────────────────────────────
def _require(pkg, install_name=None):
    try:
        return __import__(pkg)
    except ImportError:
        name = install_name or pkg
        print(f"\n  Missing: {name}\n  Run: pip install {name} --break-system-packages\n")
        sys.exit(1)

uvicorn   = _require("uvicorn")
fastapi   = _require("fastapi")
mutagen   = _require("mutagen")
pystray   = _require("pystray")
PIL       = _require("PIL", "pillow")

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                                StreamingResponse)
from mutagen import File as MutagenFile
from PIL import Image, ImageDraw, ImageFont
import pystray as _pystray
import uvicorn as _uvicorn

# ── Paths ─────────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):                    # running as PyInstaller exe
    APP_DIR = Path(sys.executable).parent
else:
    APP_DIR = Path(__file__).parent

CONFIG_PATH   = Path.home() / ".leon-music" / "config.json"
DB_PATH       = Path.home() / ".leon-music" / "library.db"
COVERS_DIR    = Path.home() / ".leon-music" / "playlist-covers"
ARTIST_PICS_DIR = Path.home() / ".leon-music" / "artist-pics"
FRONTEND_PATH = APP_DIR / "frontend.html"
PORT          = 7733
AUDIO_EXTS    = {".mp3", ".flac", ".m4a", ".aac", ".ogg", ".wav", ".opus", ".wma"}

CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
COVERS_DIR.mkdir(parents=True, exist_ok=True)
ARTIST_PICS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory sessions (cleared on restart)
_admin_tokens: set = set()      # admin API tokens (X-Admin-Token header)
_sessions: set = set()          # library access cookies (lm_session)

# ── Config ────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return {}

def save_config(cfg: dict):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_PATH, 0o600)        # config holds password hashes: owner-only (no-op on Windows)
    except OSError:
        pass

def update_config(**kw) -> dict:
    """Merge keys into config.json without clobbering everything else."""
    c = load_config()
    c.update(kw)
    save_config(c)
    return c

# ── Passwords (scrypt, salted; plain text is never stored) ───────────────────
MIN_PW_LEN = 8

def _hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"

def _check_pw(pw: str, stored: str) -> bool:
    try:
        kind, salt, want = stored.split("$")
        if kind == "pbkdf2":   # accounts made by pre-2.0 builds; upgraded to scrypt on their next login
            h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 200_000)
            return secrets.compare_digest(h.hex(), want)
        h = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return secrets.compare_digest(h.hex(), want)
    except Exception:
        return False

def _migrate_plaintext_password():
    """Older versions stored 'admin_password' in plain text. Hash it and drop the original."""
    c = load_config()
    old = c.pop("admin_password", None)
    if old is None:
        return
    if old and not c.get("admin_password_hash"):
        c["admin_password_hash"] = _hash_pw(str(old))
    save_config(c)

_migrate_plaintext_password()

def _valid_new_pw(pw) -> str:
    pw = str(pw or "")
    if len(pw) < MIN_PW_LEN:
        raise HTTPException(400, f"Password must be at least {MIN_PW_LEN} characters")
    return pw

# Brute-force protection: 5 failed logins per client per 5 minutes
_fails: dict = {}
def _rate_check(req: Request):
    ip = req.client.host if req.client else "?"
    n, first = _fails.get(ip, (0, 0.0))
    if n >= 5 and _now() - first < 300:
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
def _rate_fail(req: Request):
    ip = req.client.host if req.client else "?"
    n, first = _fails.get(ip, (0, 0.0))
    if n == 0 or _now() - first >= 300:
        n, first = 0, _now()
    _fails[ip] = (n + 1, first)
def _rate_ok(req: Request):
    _fails.pop(req.client.host if req.client else "?", None)

def _is_local_direct(req: Request) -> bool:
    """True only for a request from this machine that did not come through a reverse proxy."""
    if any(h in req.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip")):
        return False
    return bool(req.client) and req.client.host in ("127.0.0.1", "::1")

_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")

def _clean_color(v) -> str:
    v = (v or "").strip()
    return v if _HEX.match(v) else ""

def _clean_url(v):
    """'' is allowed (means unset). Returns None if not an http(s) URL."""
    v = (v or "").strip()
    if v == "" or v.lower().startswith(("http://", "https://")):
        return v
    return None

# ── Cover-logo profiles: one for Essentials covers ("ess"), one for playlist covers ("pl") ──
_LOGO_DEFAULTS = {"enabled": True, "x": 18, "y": 14, "size": 26, "opacity": 95,
                  "shadow": True, "white": False, "inside": True}
_LOGO_LIMITS   = {"x": (0, 100), "y": (0, 100), "size": (8, 60), "opacity": (10, 100)}
_LOGO_KINDS    = ("ess", "pl")
_TEXT_POSITIONS = ("top", "center", "bottom")

def _clean_logo_profile(raw, base: dict) -> dict:
    """Validate one profile; anything missing falls back to `base`."""
    out = dict(base)
    if not isinstance(raw, dict):
        return out
    for key, (lo, hi) in _LOGO_LIMITS.items():
        if key in raw:
            try:
                out[key] = round(max(lo, min(hi, float(raw[key]))), 1)
            except (TypeError, ValueError):
                raise HTTPException(400, f"{key} must be a number")
    for key in ("enabled", "shadow", "white", "inside"):
        if key in raw:
            out[key] = bool(raw[key])
    return out

def _load_logo_cfg(c: dict) -> dict:
    """Build both profiles, migrating the old single-placement keys if present."""
    pos = c.get("cover_logo_position")
    legacy = dict(_LOGO_DEFAULTS)
    legacy["enabled"] = bool(c.get("cover_logo", True))
    legacy["x"]    = c.get("cover_logo_x", {"top-right": 82, "bottom-right": 82}.get(pos, 18))
    legacy["y"]    = c.get("cover_logo_y", {"bottom-right": 86}.get(pos, 14))
    legacy["size"] = c.get("cover_logo_size", 26)
    saved = c.get("cover_logo_cfg") or {}
    try:
        return {k: _clean_logo_profile(saved.get(k) if isinstance(saved, dict) else None, legacy)
                for k in _LOGO_KINDS}
    except Exception:
        return {k: dict(legacy) for k in _LOGO_KINDS}

cfg = load_config()

# mutable globals (updated by setup/admin endpoints)
state = {
    "music_dir":     Path(os.path.normpath(cfg.get("music_dir", str(Path.home() / "Music")))).expanduser(),
    "name":          cfg.get("name", "leon.music"),
    "scanning":      False,
    "scan_found":    0,
    "scan_file":     "",
    "logo_url":      cfg.get("logo_url", ""),
    "accent":        cfg.get("accent", "#e5282a"),
    "hero_image":    cfg.get("hero_image", ""),
    "hero_tint":     cfg.get("hero_tint", ""),
    "playlist_names": cfg.get("playlist_names", {}),
    "artist_pics_online": cfg.get("artist_pics_online", True),
    "forced_essentials": cfg.get("forced_essentials", []),
    # per cover type: centre point + width as % of the cover, opacity, shadow, white tint, keep-inside
    # (older configs stored a single shared placement, which _load_logo_cfg migrates)
    "cover_logo_cfg":  _load_logo_cfg(cfg),
    # where the playlist name sits on generated playlist covers
    "cover_text_pos":  cfg.get("cover_text_pos", "center") if cfg.get("cover_text_pos", "center") in _TEXT_POSITIONS else "center",
}

# ── Tray icon (PIL-generated) ─────────────────────────────────────────────────
def _make_icon(size: int = 64) -> Image.Image:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Red circle background
    draw.ellipse([2, 2, size - 2, size - 2], fill=(229, 40, 42, 255))
    # Simple music note (stem + two beams + note heads)
    s = size / 64
    # stem
    draw.rectangle([int(36*s), int(14*s), int(41*s), int(46*s)], fill=(255,255,255,255))
    # flag / beam
    draw.polygon([
        (int(36*s), int(14*s)), (int(52*s), int(20*s)),
        (int(52*s), int(28*s)), (int(36*s), int(24*s)),
    ], fill=(255,255,255,255))
    # note head
    draw.ellipse([int(22*s), int(40*s), int(38*s), int(52*s)], fill=(255,255,255,255))
    return img

# ── Database ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tracks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            path         TEXT UNIQUE NOT NULL,
            title        TEXT,
            artist       TEXT,
            album        TEXT,
            album_artist TEXT,
            track_num    INTEGER,
            disc_num     INTEGER,
            year         INTEGER,
            genre        TEXT,
            duration     REAL,
            bitrate      INTEGER,
            size         INTEGER,
            cover_id     TEXT,
            playlist     TEXT,
            mtime        REAL,
            added_at     DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS covers (
            id   TEXT PRIMARY KEY,
            data BLOB
        );
        CREATE INDEX IF NOT EXISTS idx_artist   ON tracks(artist);
        CREATE INDEX IF NOT EXISTS idx_album    ON tracks(album);
        CREATE INDEX IF NOT EXISTS idx_playlist ON tracks(playlist);
        CREATE INDEX IF NOT EXISTS idx_added    ON tracks(added_at);
        CREATE TABLE IF NOT EXISTS plays (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            track_id  INTEGER NOT NULL,
            listener  TEXT,
            played_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_plays_time  ON plays(played_at);
        CREATE INDEX IF NOT EXISTS idx_plays_track ON plays(track_id);
    """)
    db.commit()
    db.close()
    _init_explicit()

# ── Tag reader ────────────────────────────────────────────────────────────────
def read_tags(path: Path) -> dict:
    info = {
        "title": path.stem, "artist": "Unknown Artist",
        "album": "Unknown Album", "album_artist": None,
        "track_num": None, "disc_num": None, "year": None, "genre": None,
        "duration": 0.0, "bitrate": 0, "cover_data": None,
    }
    try:
        af = MutagenFile(str(path), easy=False)
        if af is None: return info
        def get(tags, *keys, default=None):
            for k in keys:
                v = tags.get(k)
                if v:
                    val = v[0] if hasattr(v, '__getitem__') else v
                    return str(val).strip() or default
            return default
        if hasattr(af, 'info'):
            info["duration"] = getattr(af.info, 'length', 0)
            info["bitrate"]  = getattr(af.info, 'bitrate', 0)
        tags = af.tags
        if tags is None: return info
        sfx = path.suffix.lower()
        if sfx == ".mp3":
            info["title"]        = get(tags,"TIT2") or info["title"]
            info["artist"]       = get(tags,"TPE1") or info["artist"]
            info["album"]        = get(tags,"TALB") or info["album"]
            info["album_artist"] = get(tags,"TPE2")
            info["genre"]        = get(tags,"TCON")
            yr = get(tags,"TDRC","TYER")
            if yr: info["year"] = int(str(yr)[:4]) if str(yr)[:4].isdigit() else None
            trck = get(tags,"TRCK")
            if trck: info["track_num"] = int(trck.split("/")[0]) if trck.split("/")[0].isdigit() else None
            for tag in tags.values():
                if getattr(tag,"FrameID","") == "APIC":
                    info["cover_data"] = tag.data; break
        elif sfx == ".flac":
            info["title"]        = get(tags,"title") or info["title"]
            info["artist"]       = get(tags,"artist") or info["artist"]
            info["album"]        = get(tags,"album") or info["album"]
            info["album_artist"] = get(tags,"albumartist")
            info["genre"]        = get(tags,"genre")
            yr = get(tags,"date","year")
            if yr: info["year"] = int(str(yr)[:4]) if str(yr)[:4].isdigit() else None
            if hasattr(af,'pictures') and af.pictures:
                info["cover_data"] = af.pictures[0].data
        elif sfx in (".m4a",".aac",".mp4"):
            info["title"]        = get(tags,"\xa9nam") or info["title"]
            info["artist"]       = get(tags,"\xa9ART") or info["artist"]
            info["album"]        = get(tags,"\xa9alb") or info["album"]
            info["album_artist"] = get(tags,"aART")
            info["genre"]        = get(tags,"\xa9gen")
            yr = get(tags,"\xa9day")
            if yr: info["year"] = int(str(yr)[:4]) if str(yr)[:4].isdigit() else None
            trck = tags.get("trkn")
            if trck and trck[0]: info["track_num"] = trck[0][0]
            covr = tags.get("covr")
            if covr: info["cover_data"] = bytes(covr[0])
        else:
            info["title"]  = get(tags,"title") or info["title"]
            info["artist"] = get(tags,"artist") or info["artist"]
            info["album"]  = get(tags,"album") or info["album"]
            info["album_artist"] = get(tags,"albumartist")
            yr = get(tags,"date","year")
            if yr: info["year"] = int(str(yr)[:4]) if str(yr)[:4].isdigit() else None
    except Exception:
        pass
    return info

# ── Scanner ───────────────────────────────────────────────────────────────────
def scan_library():
    state["scanning"]   = True
    state["scan_found"] = 0
    state["scan_file"]  = ""
    music_dir = state["music_dir"]
    db = get_db()
    found = 0
    try:
        music_dir_str = str(music_dir)
        for root, _dirs, files in os.walk(music_dir_str):
            try:
                rel = Path(root).relative_to(music_dir)
            except ValueError:
                # Windows case-insensitive fallback
                rel_str = root[len(music_dir_str):].lstrip(os.sep)
                rel = Path(rel_str) if rel_str else Path(".")
            parts = rel.parts
            playlist = parts[0] if parts else None
            for fname in sorted(files):
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in AUDIO_EXTS:
                    continue
                mtime = fpath.stat().st_mtime
                row = db.execute("SELECT mtime FROM tracks WHERE path=?", (str(fpath),)).fetchone()
                if row and abs(row["mtime"] - mtime) < 1:
                    found += 1
                    state["scan_found"] = found
                    state["scan_file"]  = fname
                    continue
                tags = read_tags(fpath)
                cover_id = None
                if tags["cover_data"]:
                    cover_id = hashlib.md5(tags["cover_data"]).hexdigest()
                    if not db.execute("SELECT 1 FROM covers WHERE id=?", (cover_id,)).fetchone():
                        db.execute("INSERT INTO covers(id,data) VALUES(?,?)", (cover_id, tags["cover_data"]))
                db.execute("""
                    INSERT INTO tracks
                        (path,title,artist,album,album_artist,track_num,disc_num,
                         year,genre,duration,bitrate,size,cover_id,playlist,mtime)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(path) DO UPDATE SET
                        title=excluded.title, artist=excluded.artist, album=excluded.album,
                        album_artist=excluded.album_artist, track_num=excluded.track_num,
                        disc_num=excluded.disc_num, year=excluded.year, genre=excluded.genre,
                        duration=excluded.duration, bitrate=excluded.bitrate, size=excluded.size,
                        cover_id=excluded.cover_id, playlist=excluded.playlist, mtime=excluded.mtime
                """, (
                    str(fpath), tags["title"], tags["artist"], tags["album"],
                    tags["album_artist"], tags["track_num"], tags["disc_num"],
                    tags["year"], tags["genre"], tags["duration"], tags["bitrate"],
                    fpath.stat().st_size, cover_id, playlist, mtime,
                ))
                db.execute("UPDATE tracks SET explicit=? WHERE path=?", (_explicit_flag(fpath, tags["title"]), str(fpath)))
                found += 1
                state["scan_found"] = found
                state["scan_file"]  = fname
                if found % 20 == 0:
                    db.commit()
        db.commit()
    finally:
        db.close()
        state["scanning"]  = False

# ── FastAPI ───────────────────────────────────────────────────────────────────
api = FastAPI(title="leon.music", docs_url=None, redoc_url=None)
# No CORS middleware: the player is served from this same origin, so cross-site pages get no access.

# ── Library access gate (optional library password) ──────────────────────────
_OPEN_PATHS = {"/api/status", "/api/setup", "/api/library/login", "/api/library/logout",
               "/api/admin/login", "/api/admin/check", "/api/auth/me", "/api/auth/login", "/api/auth/logout"}

def _lib_locked() -> bool:
    """Locked when a library password is set or any user accounts exist."""
    return bool(load_config().get("library_password_hash")) or _auth_required()

def _has_access(req: Request) -> bool:
    if not _lib_locked():
        return True
    return (req.cookies.get("lm_session", "") in _sessions or _is_admin(req)
            or _session_user(req) is not None)

@api.middleware("http")
async def _library_gate(request: Request, call_next):
    p = request.url.path
    if p.startswith("/api/") and p not in _OPEN_PATHS and not _has_access(request):
        return JSONResponse({"detail": "Library locked"}, status_code=401)
    return await call_next(request)

def _login_response(req: Request, payload: dict) -> JSONResponse:
    """Hand out a library-access cookie (audio/img tags can't send headers, so a cookie is needed)."""
    token = secrets.token_hex(32)
    _sessions.add(token)
    resp = JSONResponse(payload)
    secure = req.url.scheme == "https" or req.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie("lm_session", token, httponly=True, samesite="lax",
                    secure=secure, max_age=30 * 86400)
    return resp

@api.post("/api/library/login")
async def api_library_login(req: Request):
    _rate_check(req)
    body = await req.json()
    stored = load_config().get("library_password_hash", "")
    if stored and not _check_pw(str(body.get("password", "")), stored):
        _rate_fail(req)
        raise HTTPException(401, "Wrong password")
    _rate_ok(req)
    return _login_response(req, {"ok": True})

@api.post("/api/library/logout")
def api_library_logout(req: Request):
    _sessions.discard(req.cookies.get("lm_session", ""))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("lm_session")
    return resp

@api.get("/api/status")
def api_status(req: Request):
    if not _has_access(req):                      # locked: reveal only what the login screen needs
        return {"name": state["name"], "locked": True, "tracks": 0, "albums": 0,
                "music_dir": "", "scanning": False, "scan_found": 0, "scan_file": "",
                "logo_url": "", "accent": state["accent"], "hero_image": "", "hero_tint": "",
                "cover_logo_cfg": state["cover_logo_cfg"], "cover_text_pos": state["cover_text_pos"]}
    db = get_db()
    total  = db.execute("SELECT COUNT(*) FROM tracks").fetchone()[0]
    albums = db.execute("SELECT COUNT(DISTINCT album) FROM tracks").fetchone()[0]
    db.close()
    return {
        "locked": False,
        "name": state["name"], "tracks": total, "albums": albums,
        "music_dir": str(state["music_dir"]) if _is_admin(req) else "",
        "scanning": state["scanning"],
        "scan_found": state["scan_found"],
        "scan_file": state["scan_file"],
        "logo_url": state["logo_url"],
        "accent": state["accent"],
        "hero_image": state["hero_image"],
        "hero_tint": state["hero_tint"],
        "cover_logo_cfg": state["cover_logo_cfg"],
        "cover_text_pos": state["cover_text_pos"],
    }

@api.post("/api/setup")
async def api_setup(req: Request):
    # First run (nothing configured yet) is open so the welcome wizard works;
    # once a library is configured, only an admin may change it.
    first_run = not load_config().get("music_dir")
    if not first_run:
        _require_admin(req)
    body = await req.json()
    # An admin password is mandatory the first time, so a fresh server can never be left open.
    if first_run and not load_config().get("admin_password_hash"):
        body["admin_password"] = _valid_new_pw(body.get("admin_password"))
    raw_dir   = (body.get("music_dir") or "").strip() or str(Path.home() / "Music")
    music_dir = Path(os.path.normpath(raw_dir)).expanduser()
    name      = (body.get("name") or "").strip() or "leon.music"
    if not music_dir.exists():
        raise HTTPException(400, f"Folder not found: {music_dir}")
    state["music_dir"] = music_dir
    state["name"]      = name
    upd = {"music_dir": str(music_dir), "name": name}
    if body.get("admin_password"):
        upd["admin_password_hash"] = _hash_pw(_valid_new_pw(body["admin_password"]))
    update_config(**upd)
    threading.Thread(target=scan_library, daemon=True).start()
    return {"status": "ok", "music_dir": str(music_dir), "name": name}

@api.get("/api/scan/start")
def api_scan_start(req: Request):
    _require_admin(req)
    if not state["scanning"]:
        threading.Thread(target=scan_library, daemon=True).start()
    return {"status": "scanning"}

@api.get("/api/scan/status")
def api_scan_status():
    return {"scanning": state["scanning"], "found": state["scan_found"], "file": state["scan_file"]}

@api.get("/api/tracks")
def api_tracks(album:Optional[str]=None, artist:Optional[str]=None,
               playlist:Optional[str]=None, search:Optional[str]=None,
               limit:int=500, offset:int=0):
    db = get_db()
    q = "SELECT id,title,artist,album,track_num,disc_num,year,duration,cover_id,playlist FROM tracks WHERE 1=1"
    p: list = []
    if album:    q += " AND album=?";    p.append(album)
    if artist:   q += " AND COALESCE(album_artist,artist)=?"; p.append(artist)   # same key as /api/artists
    if playlist: q += " AND playlist=?"; p.append(playlist)
    if search:
        q += " AND (title LIKE ? OR artist LIKE ? OR album LIKE ?)"; like=f"%{search}%"; p+=[like,like,like]
    order = "disc_num NULLS LAST, track_num NULLS LAST, title"
    if artist and not album:
        order = "album, " + order            # group an artist's songs by album
    q += f" ORDER BY {order} LIMIT ? OFFSET ?"
    p += [limit, offset]
    rows = db.execute(q, p).fetchall(); db.close()
    return [dict(r) for r in rows]

@api.get("/api/albums")
def api_albums():
    db = get_db()
    rows = db.execute("""
        SELECT album, COALESCE(album_artist,artist) as artist, year,
               COUNT(*) as track_count, SUM(duration) as total_duration, MIN(cover_id) as cover_id
        FROM tracks GROUP BY album ORDER BY album
    """).fetchall(); db.close()
    return [dict(r) for r in rows]

@api.get("/api/artists")
def api_artists():
    db = get_db()
    rows = db.execute("""
        SELECT COALESCE(album_artist,artist) as name,
               COUNT(DISTINCT album) as album_count, COUNT(*) as track_count,
               MIN(cover_id) as cover_id
        FROM tracks GROUP BY name ORDER BY name
    """).fetchall(); db.close()
    forced = {n.lower() for n in state["forced_essentials"]}
    out = []
    for r in rows:
        d = dict(r)
        d["forced"] = (d["name"] or "").lower() in forced     # admin forced an Essentials page
        out.append(d)
    return out

@api.get("/api/playlists")
def api_playlists():
    db = get_db()
    rows = db.execute("""
        SELECT playlist as name, COUNT(*) as track_count, SUM(duration) as total_duration
        FROM tracks WHERE playlist IS NOT NULL GROUP BY playlist ORDER BY playlist
    """).fetchall(); db.close()
    out = []
    for r in rows:
        d = dict(r)
        d["display_name"] = state["playlist_names"].get(d["name"], d["name"])
        out.append(d)
    return out

@api.get("/api/cover/{cover_id}")
def api_cover(cover_id: str):
    db = get_db()
    row = db.execute("SELECT data FROM covers WHERE id=?", (cover_id,)).fetchone(); db.close()
    if not row: raise HTTPException(404)
    return Response(content=row["data"], media_type="image/jpeg",
                    headers={"Cache-Control":"public,max-age=86400"})

@api.get("/api/stream/{track_id}")
def api_stream(track_id: int, request: Request):
    db = get_db()
    row = db.execute("SELECT path,size FROM tracks WHERE id=?", (track_id,)).fetchone(); db.close()
    if not row: raise HTTPException(404)
    path = Path(row["path"])
    if not path.exists(): raise HTTPException(404, "File missing from disk")
    size = path.stat().st_size
    mime = mimetypes.guess_type(str(path))[0] or "audio/mpeg"
    rng  = request.headers.get("range")
    if rng:
        m = re.match(r"bytes=(\d+)-(\d*)", rng)
        if m:
            start = int(m.group(1))
            end   = int(m.group(2)) if m.group(2) else size - 1
            end   = min(end, size - 1)
            length = end - start + 1
            def _iter():
                with open(path,"rb") as f:
                    f.seek(start); rem = length
                    while rem > 0:
                        chunk = f.read(min(65536, rem))
                        if not chunk: break
                        rem -= len(chunk); yield chunk
            return StreamingResponse(_iter(), status_code=206, media_type=mime, headers={
                "Content-Range": f"bytes {start}-{end}/{size}",
                "Accept-Ranges": "bytes", "Content-Length": str(length),
            })
    return FileResponse(str(path), media_type=mime,
                        headers={"Accept-Ranges":"bytes","Content-Length":str(size)})

# ── Admin auth helper ─────────────────────────────────────────────────────────
def _is_admin(req: Request) -> bool:
    token = req.headers.get("X-Admin-Token", "")
    if token and token in _admin_tokens:
        return True
    sess = req.cookies.get("lm_session", "")
    if not sess:
        return False
    db = get_db()
    try:
        r = db.execute("""SELECT s.user_id, COALESCE(u.is_admin,0) FROM sessions s LEFT JOIN users u ON u.id=s.user_id
                          WHERE s.token=? AND s.expires>?""", (sess, _now())).fetchone()
    except sqlite3.OperationalError:
        r = None
    finally:
        db.close()
    return bool(r) and (r[0] == 0 or r[1] == 1)

def _require_admin(req: Request):
    if not _is_admin(req):
        raise HTTPException(401, "Admin login required")

@api.get("/api/admin/check")
def api_admin_check(req: Request):
    """Lets the player ask 'is my saved token still valid?' without triggering a 401."""
    return {"admin": _is_admin(req)}

@api.post("/api/admin/login")
async def api_admin_login(req: Request):
    _rate_check(req)
    body = await req.json()
    password = str(body.get("password", ""))
    stored = load_config().get("admin_password_hash", "")
    if stored:
        if not _check_pw(password, stored):
            _rate_fail(req)
            raise HTTPException(401, "Wrong password")
    elif not _is_local_direct(req):
        # Legacy installs with no password: only the machine running leon.music may log in (to set one)
        raise HTTPException(403, "No admin password is set. Open leon.music on the computer running it and set one in Admin → Security.")
    _rate_ok(req)
    token = secrets.token_hex(32)
    _admin_tokens.add(token)
    return _login_response(req, {"token": token})

@api.get("/api/admin/settings")
def api_admin_get(req: Request):
    _require_admin(req)
    c = load_config()
    return {
        "logo_url":      c.get("logo_url", ""),
        "name":          state["name"],
        "music_dir":     str(state["music_dir"]),
        "has_password":  bool(c.get("admin_password_hash", "")),
        "has_library_password": bool(c.get("library_password_hash", "")),
        "accent":        state["accent"],
        "hero_image":    state["hero_image"],
        "hero_tint":     state["hero_tint"],
        "artist_pics_online": state["artist_pics_online"],
        "lyrics_online": state.get("lyrics_online", True),
        "forced_essentials": state["forced_essentials"],
        "cover_logo_cfg":      state["cover_logo_cfg"],
        "cover_text_pos":      state["cover_text_pos"],
    }

@api.post("/api/admin/settings")
async def api_admin_set(req: Request):
    _require_admin(req)
    body = await req.json()
    c = load_config()
    if "logo_url"      in body: c["logo_url"]      = body["logo_url"];      state["logo_url"]      = body["logo_url"]
    if "name"          in body:
        v = str(body["name"]).strip()[:60] or "leon.music"
        c["name"] = v; state["name"] = v
    if "accent" in body:
        v = _clean_color(body["accent"]) or "#e5282a"
        c["accent"] = v; state["accent"] = v
    if "hero_tint" in body:
        v = _clean_color(body["hero_tint"])          # "" = follow accent
        c["hero_tint"] = v; state["hero_tint"] = v
    if "hero_image" in body:
        v = _clean_url(body["hero_image"])
        if v is None:
            raise HTTPException(400, "Hero image must be an http(s) URL")
        c["hero_image"] = v; state["hero_image"] = v
    if "artist_pics_online" in body:
        v = bool(body["artist_pics_online"])
        c["artist_pics_online"] = v; state["artist_pics_online"] = v
    if "lyrics_online" in body:
        v = bool(body["lyrics_online"])
        c["lyrics_online"] = v; state["lyrics_online"] = v
    if "cover_logo_cfg" in body:
        raw = body["cover_logo_cfg"]
        if not isinstance(raw, dict):
            raise HTTPException(400, "cover_logo_cfg must be an object")
        new = {k: _clean_logo_profile(raw.get(k), state["cover_logo_cfg"][k]) for k in _LOGO_KINDS}
        c["cover_logo_cfg"] = new; state["cover_logo_cfg"] = new
    if "cover_text_pos" in body:
        v = body["cover_text_pos"]
        if v not in _TEXT_POSITIONS:
            raise HTTPException(400, "cover_text_pos must be top, center or bottom")
        c["cover_text_pos"] = v; state["cover_text_pos"] = v
    if "forced_essentials" in body:
        raw = body["forced_essentials"]
        if not isinstance(raw, list):
            raise HTTPException(400, "forced_essentials must be a list")
        seen, names = set(), []
        for n in raw[:500]:
            n = str(n).strip()[:120]
            if n and n.lower() not in seen:
                seen.add(n.lower()); names.append(n)
        c["forced_essentials"] = names; state["forced_essentials"] = names
    if body.get("admin_password"):
        c["admin_password_hash"] = _hash_pw(_valid_new_pw(body["admin_password"]))
        c.pop("admin_password", None)
    if body.get("library_password"):
        c["library_password_hash"] = _hash_pw(_valid_new_pw(body["library_password"]))
        _sessions.clear()                      # everyone must sign in with the new password
    elif body.get("clear_library_password"):
        c.pop("library_password_hash", None)
        _sessions.clear()
    save_config(c)
    return {"status": "ok"}

# ── Playlist cover generation ─────────────────────────────────────────────────
def _safe_name(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in "-_ ").strip().replace(" ", "_") or "playlist"

@api.post("/api/playlist/{name}/cover")
async def api_gen_cover(name: str, req: Request):
    _require_admin(req)
    body = await req.json()
    image_url = body.get("image_url", "").strip()
    label = state["playlist_names"].get(name, name)   # cover text follows the display name
    if not image_url:
        raise HTTPException(400, "image_url required")
    try:
        req2 = urllib.request.Request(image_url, headers={"User-Agent": "leon.music/1.0"})
        with urllib.request.urlopen(req2, timeout=10) as r:
            img_data = r.read()
    except Exception as e:
        raise HTTPException(400, f"Could not download image: {e}")
    try:
        base = Image.open(io.BytesIO(img_data)).convert("RGBA")
        base = base.resize((600, 600), Image.LANCZOS)
        # Gradient overlay (bottom-heavy dark)
        overlay = Image.new("RGBA", (600, 600), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        for y in range(600):
            alpha = int(80 + (y / 600) * 160)
            od.line([(0, y), (600, y)], fill=(0, 0, 0, alpha))
        base = Image.alpha_composite(base, overlay)
        draw = ImageDraw.Draw(base)
        # Font: try common paths
        font_size = max(36, min(80, int(600 / max(len(label), 1) * 0.9)))
        text = label.upper()
        font_path = None
        for fp in ["arialbd.ttf", "Arial Bold.ttf",
                   "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                   "/System/Library/Fonts/Helvetica.ttc"]:
            try: ImageFont.truetype(fp, font_size); font_path = fp; break
            except: pass
        def _font(sz):
            return ImageFont.truetype(font_path, sz) if font_path else ImageFont.load_default()
        # Shrink until the name fits inside the cover with a margin (long names used to overflow)
        font = _font(font_size)
        bb = draw.textbbox((0, 0), text, font=font)
        while font_path and (bb[2] - bb[0]) > 540 and font_size > 14:
            font_size -= 4
            font = _font(font_size)
            bb = draw.textbbox((0, 0), text, font=font)
        tw, th = bb[2] - bb[0], bb[3] - bb[1]
        # textbbox starts at an offset from the draw origin; subtract it so the ink is truly centred
        margin = int(600 * 0.14)
        pos = state.get("cover_text_pos", "center")
        x = (600 - tw) // 2 - bb[0]
        if pos == "top":      y = margin - bb[1]
        elif pos == "bottom": y = 600 - margin - th - bb[1]
        else:                 y = (600 - th) // 2 - bb[1]
        # Shadow
        draw.text((x + 3, y + 3), label.upper(), font=font, fill=(0, 0, 0, 180))
        draw.text((x, y), label.upper(), font=font, fill=(255, 255, 255, 255))
        # Save
        out = io.BytesIO()
        base.convert("RGB").save(out, "JPEG", quality=90)
        cover_bytes = out.getvalue()
    except Exception as e:
        raise HTTPException(500, f"Image processing failed: {e}")
    cover_path = COVERS_DIR / f"{_safe_name(name)}.jpg"
    cover_path.write_bytes(cover_bytes)
    return Response(content=cover_bytes, media_type="image/jpeg",
                    headers={"Cache-Control": "no-cache"})

@api.get("/api/playlist/{name}/cover")
def api_playlist_cover(name: str):
    p = COVERS_DIR / f"{_safe_name(name)}.jpg"
    if not p.exists():
        raise HTTPException(404)
    return Response(content=p.read_bytes(), media_type="image/jpeg",
                    headers={"Cache-Control": "no-cache"})

# ── Playlist rename (display name only; the folder key never changes) ────────
@api.post("/api/playlist/{name}/rename")
async def api_rename_playlist(name: str, req: Request):
    _require_admin(req)
    db = get_db()
    exists = db.execute("SELECT 1 FROM tracks WHERE playlist=? LIMIT 1", (name,)).fetchone()
    db.close()
    if not exists:
        raise HTTPException(404, "Playlist not found")
    body = await req.json()
    display = (body.get("display_name") or "").strip()[:60]
    names = dict(state["playlist_names"])
    if display and display != name:
        names[name] = display
    else:
        names.pop(name, None)
        display = name
    state["playlist_names"] = names
    update_config(playlist_names=names)
    return {"name": name, "display_name": display}

# ── Radio ─────────────────────────────────────────────────────────────────────
RADIO_UA = "leon.music/1.0"
_radio_cache: dict = {}          # station id -> (timestamp, result)

def _stations() -> list:
    return load_config().get("stations", [])

def _station(sid: str):
    if sid.startswith("live-"):                       # one of our own broadcast stations
        st = next((s for s in _live_stations() if s["id"] == sid), None)
        return st and {**st, "bc": st["sid"]}
    return next((s for s in _stations() if s.get("id") == sid), None)

@api.get("/api/radio/stations")
def api_radio_stations():
    return _live_stations() + [
        {"id": s["id"], "name": s["name"], "url": s["url"], "logo": s.get("logo", ""),
         "genre": s.get("genre", "")}
        for s in _stations()]

@api.post("/api/admin/radio")
async def api_admin_radio_add(req: Request):
    _require_admin(req)
    body = await req.json()
    name = (body.get("name") or "").strip()[:80]
    url  = _clean_url(body.get("url"))
    logo = _clean_url(body.get("logo"))
    meta = _clean_url(body.get("meta_url"))
    if not name:
        raise HTTPException(400, "Station name required")
    if not url:
        raise HTTPException(400, "Stream URL must start with http:// or https://")
    if logo is None or meta is None:
        raise HTTPException(400, "Logo and metadata URLs must start with http:// or https://")
    c = load_config()
    stations = c.get("stations", [])
    st = {"id": secrets.token_hex(4), "name": name, "url": url, "logo": logo, "meta_url": meta}
    stations.append(st)
    c["stations"] = stations
    save_config(c)
    return st

@api.delete("/api/admin/radio/{sid}")
def api_admin_radio_delete(sid: str, req: Request):
    _require_admin(req)
    c = load_config()
    c["stations"] = [s for s in c.get("stations", []) if s.get("id") != sid]
    save_config(c)
    _radio_cache.pop(sid, None)
    return {"status": "ok"}

def _fetch_bytes(url: str, timeout: int = 5, limit: int = 1_000_000) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": RADIO_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(limit)

def _icecast_status(stream_url: str, meta_url: str = ""):
    """Read Icecast's status-json.xsl and return info for this stream's mount."""
    u = urlparse(stream_url)
    status_url = meta_url or f"{u.scheme}://{u.netloc}/status-json.xsl"
    data = json.loads(_fetch_bytes(status_url).decode("utf-8", "replace"))
    src = (data.get("icestats") or {}).get("source")
    if isinstance(src, dict):
        src = [src]
    if not src:
        return None
    pick = next((s for s in src if urlparse(s.get("listenurl", "") or "").path == u.path), None)
    if pick is None and len(src) == 1:
        pick = src[0]
    if pick is None:
        return None
    title  = (pick.get("title") or "").strip()
    artist = (pick.get("artist") or "").strip()
    if artist and title and not title.lower().startswith(artist.lower()):
        title = f"{artist} - {title}"
    if not title:
        title = (pick.get("yp_currently_playing") or "").strip()
    return {"title": title, "name": pick.get("server_name"), "genre": pick.get("genre"),
            "listeners": pick.get("listeners"),
            "bitrate": pick.get("bitrate") or pick.get("audio_bitrate")}

def _icy_meta(url: str, hops: int = 0) -> dict:
    """Generic Icecast/Shoutcast: ask for in-stream metadata and read one block.
    Uses a raw socket because Shoutcast v1 answers 'ICY 200 OK', which http.client rejects."""
    u = urlparse(url)
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    sock = socket.create_connection((u.hostname, port), timeout=6)
    try:
        if https:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        sock.settimeout(8)
        sock.sendall((f"GET {path} HTTP/1.0\r\nHost: {u.netloc}\r\nUser-Agent: {RADIO_UA}\r\n"
                      f"Icy-MetaData: 1\r\nConnection: close\r\n\r\n").encode())
        f = sock.makefile("rb")
        status = f.readline().decode("latin-1").split()
        code = int(status[1]) if len(status) > 1 and status[1].isdigit() else 0
        headers = {}
        while True:
            line = f.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        if code in (301, 302, 303, 307, 308) and headers.get("location") and hops < 3:
            return _icy_meta(urljoin(url, headers["location"]), hops + 1)
        info = {"title": "", "name": headers.get("icy-name"), "genre": headers.get("icy-genre"),
                "bitrate": headers.get("icy-br")}
        if code != 200:
            return info
        try:
            metaint = int(headers.get("icy-metaint") or 0)
        except ValueError:
            metaint = 0
        if 0 < metaint <= 262144:
            remaining = metaint
            while remaining > 0:
                chunk = f.read(min(remaining, 8192))
                if not chunk:
                    return info
                remaining -= len(chunk)
            lb = f.read(1)
            if lb and lb[0] > 0:
                meta = f.read(lb[0] * 16).decode("utf-8", "replace")
                m = re.search(r"StreamTitle='(.*?)';", meta, re.S)
                if m:
                    info["title"] = m.group(1).strip()
        return info
    finally:
        try:
            sock.close()
        except Exception:
            pass

def radio_now(st: dict) -> dict:
    if st.get("bc"):                                  # our own station: we know exactly what's playing
        s = _bc_status.get(st["bc"], {})
        now = s.get("now") or {}
        res = {"title": f'{now.get("artist") or "Unknown"} - {now.get("title")}' if now.get("title") else "",
               "name": st["name"], "genre": st.get("tagline"), "listeners": None,
               "bitrate": _bc_cfg().get("bitrate"), "source": "live", "state": s.get("state", "stopped"),
               "program": s.get("program"), "now": now or None}
        cached = _radio_cache.get(st["id"])
        if cached and _now() - cached[0] < 20:
            res["listeners"] = cached[1]
        elif s.get("state") == "live":
            try:
                res["listeners"] = (_icecast_status(st["url"]) or {}).get("listeners")
            except Exception:
                pass
            _radio_cache[st["id"]] = (_now(), res["listeners"])
        return res
    cached = _radio_cache.get(st["id"])
    if cached and _now() - cached[0] < 8:
        return cached[1]
    res = {"title": "", "name": None, "genre": None, "listeners": None, "bitrate": None, "source": None}
    try:
        d = _icecast_status(st["url"], st.get("meta_url", ""))
        if d:
            res.update({k: v for k, v in d.items() if v not in (None, "")})
            res["source"] = "icecast"
    except Exception:
        pass
    if not res["title"]:
        try:
            d = _icy_meta(st["url"])
            for k in ("title", "name", "genre", "bitrate"):
                if d.get(k) and not res.get(k):
                    res[k] = d[k]
            res["source"] = res["source"] or "icy"
        except Exception:
            if not res["source"]:
                res["error"] = "unreachable"
    _radio_cache[st["id"]] = (_now(), res)
    return res

@api.get("/api/radio/{sid}/now")
def api_radio_now(sid: str):
    st = _station(sid)
    if not st:
        raise HTTPException(404, "Unknown station")
    return radio_now(st)

@api.get("/api/radio/{sid}/stream")
def api_radio_stream(sid: str):
    """Relay a station through this server (used when the page is https but the stream is http)."""
    st = _station(sid)
    if not st:
        raise HTTPException(404, "Unknown station")
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(st["url"], headers={"User-Agent": RADIO_UA}), timeout=10)
    except Exception as e:
        raise HTTPException(502, f"Could not open stream: {e}")
    ctype = r.headers.get_content_type() or "audio/mpeg"
    def _iter():
        try:
            while True:
                chunk = r.read(8192)
                if not chunk:
                    break
                yield chunk
        finally:
            r.close()
    return StreamingResponse(_iter(), media_type=ctype, headers={"Cache-Control": "no-cache"})

# ── Live radio: our own stations, broadcast to Icecast ───────────────────────
# Each enabled station runs a _Caster thread: it picks songs from the playlists
# scheduled for "now", encodes them to constant-bitrate MP3 with ffmpeg, and sends
# them to Icecast as a source client, paced to real time with a few seconds of lead.
import shutil as _shutil
import subprocess as _subprocess
import random as _random
import datetime as _dt
from urllib.parse import urlencode as _urlencode

FFMPEG = _shutil.which("ffmpeg") or next(
    (str(p) for p in (APP_DIR / "ffmpeg.exe", APP_DIR / "ffmpeg") if p.exists()), None)
_NO_WINDOW = getattr(_subprocess, "CREATE_NO_WINDOW", 0)

STATION_TEMPLATES = [
    {"key": "one",       "name": "1",         "tagline": "The flagship. The best of everything, all day.",
     "style": "numeral", "c1": "#ff2d2d", "c2": "#ff7a1a", "match": []},
    {"key": "hits",      "name": "Hits",      "tagline": "Wall-to-wall hits, nothing but bangers.",
     "style": "echo",    "c1": "#2b5cff", "c2": "#19c6ff", "match": ["hit", "top", "pop", "fav"]},
    {"key": "club",      "name": "Club",      "tagline": "House, dance and late-night energy.",
     "style": "bubble",  "c1": "#141414", "c2": "#ff2fa8", "match": ["club", "dance", "house", "edm", "party", "techno"]},
    {"key": "chill",     "name": "Chill",     "tagline": "Slow down and tune in.",
     "style": "wave",    "c1": "#0aa2ff", "c2": "#53e0ff", "match": ["chill", "lofi", "lo-fi", "relax", "late", "calm", "sleep"]},
    {"key": "country",   "name": "Country",   "tagline": "Back roads and big choruses.",
     "style": "sunset",  "c1": "#173a8f", "c2": "#ffb31a", "match": ["country", "folk", "americana"]},
    {"key": "hiphop",    "name": "Hip-Hop",   "tagline": "Rap and R&B, around the clock.",
     "style": "block",   "c1": "#111111", "c2": "#f6d21b", "match": ["hip", "rap", "rnb", "r&b", "trap", "drill"]},
    {"key": "throwback", "name": "Throwback", "tagline": "Yesterday's favourites, today.",
     "style": "stripes", "c1": "#ff5b2e", "c2": "#ffc21a", "match": ["throw", "old", "classic", "retro", "80", "90", "00"]},
    {"key": "latino",    "name": "Latino",    "tagline": "Reggaeton, Latin pop and more.",
     "style": "tilt",    "c1": "#e0195c", "c2": "#ff8a00", "match": ["latin", "latino", "reggaeton", "spanish"]},
    {"key": "focus",     "name": "Focus",     "tagline": "Music to get things done.",
     "style": "ring",    "c1": "#2c8c6e", "c2": "#8fe3b6", "match": ["focus", "study", "work", "ambient", "instrumental"]},
    {"key": "party",     "name": "Party",     "tagline": "Turn it up.",
     "style": "confetti", "c1": "#7a2cff", "c2": "#ff3d8b", "match": ["party", "gym", "workout", "hype"]},
    {"key": "holiday",   "name": "Holiday",   "tagline": "Christmas music, all season long.",
     "style": "lights",  "c1": "#0f9d3a", "c2": "#e5282a", "single": True,
     "match": ["christmas", "xmas", "holiday", "jul", "noel", "navidad", "weihnacht"]},
]
_TEMPLATE_BY_KEY = {t["key"]: t for t in STATION_TEMPLATES}
_bc_status: dict = {}       # station id -> live status dict
_casters: dict = {}         # station id -> _Caster
_casters_lock = threading.Lock()

def _bc_cfg() -> dict:
    return load_config().get("broadcast") or {}

def _bc_station(sid: str):
    return next((s for s in _bc_cfg().get("stations", []) if s.get("id") == sid), None)

def _xml(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))

# ── Logos (original SVG designs; system fonts because <img> SVGs can't use web fonts) ──
_LOGO_FONT = "'Arial Black','Helvetica Neue',Arial,'Segoe UI Black',sans-serif"

def _fit(text: str, size: int, max_w: int):
    """Font size and optional textLength so a name always fits."""
    est = len(text) * size * 0.74
    if est <= max_w:
        return size, ""
    size2 = max(int(size * max_w / est), int(size * .55))
    est2 = len(text) * size2 * 0.74
    return size2, (f' textLength="{max_w}" lengthAdjust="spacingAndGlyphs"' if est2 > max_w else "")

def station_logo_svg(name: str, style: str, c1: str, c2: str, brand: str) -> str:
    c1 = _clean_color(c1) or "#e5282a"
    c2 = _clean_color(c2) or c1
    W = 600
    label = name.strip() or "Radio"
    up = label.upper()
    defs = (f'<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient>')
    bg = "#f6f5f1"
    art = ""
    T = lambda x, y, txt, size, fill, extra="", anchor="middle": (
        f'<text x="{x}" y="{y}" font-family="{_LOGO_FONT}" font-weight="900" font-size="{size}" '
        f'fill="{fill}" text-anchor="{anchor}"{extra}>{_xml(txt)}</text>')
    if style == "numeral":
        s, tl = _fit(label, 400, 470)
        art = (f'<circle cx="300" cy="250" r="190" fill="{c2}" opacity=".12"/>'
               + T(300, 250 + s * .36, label, s, "url(#g)", tl + ' letter-spacing="-8"'))
    elif style == "echo":
        s, tl = _fit(up, 150, 500)
        y = 265 + s * .18
        art = "".join(T(300, y + d, up, s, "none", tl + f' stroke="{c2}" stroke-width="3" opacity="{o}" font-style="italic"')
                      for d, o in ((-118, .35), (-59, .6)))
        art += T(300, y, up, s, "url(#g)", tl + ' font-style="italic"')
        art += "".join(T(300, y + d, up, s, "none", tl + f' stroke="{c1}" stroke-width="3" opacity="{o}" font-style="italic"')
                       for d, o in ((59, .6), (118, .35)))
    elif style == "bubble":
        s, tl = _fit(label.lower(), 190, 500)
        y = 250 + s * .3
        art = (T(312, y + 12, label.lower(), s, c2, tl + f' stroke="{c2}" stroke-width="26" stroke-linejoin="round"')
               + T(300, y, label.lower(), s, c1, tl + f' stroke="{c1}" stroke-width="26" stroke-linejoin="round"')
               + T(300, y, label.lower(), s, "#fff", tl))
    elif style == "wave":
        s, tl = _fit(label.lower(), 190, 500)
        y = 240 + s * .3
        art = (T(300, y, label.lower(), s, "url(#g)", tl)
               + f'<path d="M80 {y+50} q55 -34 110 0 t110 0 t110 0 t110 0" fill="none" stroke="{c2}" '
                 f'stroke-width="14" stroke-linecap="round" opacity=".75"/>')
    elif style == "sunset":
        s, tl = _fit(up, 140, 520)
        art = (f'<circle cx="300" cy="270" r="150" fill="{c2}"/>'
               f'<rect x="0" y="270" width="600" height="200" fill="{bg}"/>'
               + "".join(f'<rect x="150" y="{200+i*22}" width="300" height="7" fill="{bg}"/>' for i in range(4))
               + T(300, 300, up, s, c1, tl))
    elif style == "block":
        s, tl = _fit(up, 130, 440)
        art = (f'<rect x="92" y="148" width="436" height="210" rx="18" fill="{c2}"/>'
               f'<rect x="72" y="128" width="436" height="210" rx="18" fill="{c1}"/>'
               + T(290, 233 + s * .36, up, s, c2, tl))
    elif style == "stripes":
        s, tl = _fit(up, 120, 500)
        cols = [c1, c2, "#ff8f3a", c1]
        art = ("".join(f'<rect x="0" y="{110+i*34}" width="600" height="22" fill="{cols[i]}" opacity=".9"/>'
                       for i in range(4))
               + T(300, 330, up, s, "#1b1b1b", tl + ' font-style="italic"'))
    elif style == "tilt":
        s, tl = _fit(up, 140, 470)
        art = (f'<g transform="rotate(-8 300 250)"><rect x="40" y="160" width="520" height="170" fill="url(#g)"/>'
               + T(300, 245 + s * .36, up, s, "#fff", tl) + '</g>')
    elif style == "ring":
        s, tl = _fit(label.lower(), 130, 340)
        art = (f'<circle cx="300" cy="250" r="170" fill="none" stroke="url(#g)" stroke-width="30"/>'
               + T(300, 250 + s * .34, label.lower(), s, c1, tl))
    elif style == "confetti":
        rng = _random.Random(label)
        dots = "".join(f'<rect x="{rng.randint(30,560)}" y="{rng.randint(40,390)}" width="{rng.randint(10,22)}" '
                       f'height="{rng.randint(10,22)}" rx="4" fill="{rng.choice([c1, c2, "#ffd23f", "#2ec5ff"])}" '
                       f'transform="rotate({rng.randint(0,90)})" opacity=".8"/>' for _ in range(26))
        s, tl = _fit(up, 150, 500)
        art = dots + T(300, 250 + s * .36, up, s, "url(#g)", tl + ' stroke="#fff" stroke-width="10" paint-order="stroke"')
    elif style == "lights":
        s, tl = _fit(up, 150, 520)
        y = 255 + s * .3
        bulbs = ""
        for k in range(11):
            x = 40 + k * 52
            cy = 92 + (14 if k % 2 else -6) + (k * 7 % 9)
            col = ["#e5282a", "#ffc21a", "#1f6bff", "#0f9d3a", "#ff7a1a"][k % 5]
            bulbs += (f'<rect x="{x-5}" y="{cy-22}" width="10" height="9" rx="2" fill="#2d4a2b"/>'
                      f'<ellipse cx="{x}" cy="{cy}" rx="11" ry="17" fill="{col}" transform="rotate({(k%3-1)*18} {x} {cy-18})"/>'
                      f'<ellipse cx="{x-3}" cy="{cy-5}" rx="3" ry="6" fill="#fff" opacity=".45"/>')
        art = (f'<path d="M10 70 Q150 105 300 72 T590 74" fill="none" stroke="#2d4a2b" stroke-width="4"/>' + bulbs
               + T(300, y, up, s, c1, tl + f' font-style="italic" stroke="{c1}" stroke-width="6" stroke-linejoin="round"')
               + f'<g fill="{c2}">' + "".join(f'<path d="M{x} {y+40} l6 14 l15 2 l-11 10 l3 15 l-13 -7 l-13 7 l3 -15 l-11 -10 l15 -2z" opacity=".85"/>'
                                            for x in (120, 300, 480)) + '</g>')
    else:  # plain custom
        s, tl = _fit(up, 150, 500)
        art = T(300, 250 + s * .36, up, s, "url(#g)", tl)
    brand = (brand or "leon.music").strip()[:28]
    fs, _ = _fit(brand + " radio", 40, 470)
    footer = (f'<text x="300" y="540" font-family="{_LOGO_FONT}" font-weight="900" font-size="{fs}" '
              f'text-anchor="middle" letter-spacing="-1"><tspan fill="#151515">{_xml(brand)}</tspan>'
              f'<tspan fill="{c1 if style not in ("bubble", "block") else c2}"> radio</tspan></text>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {W}" width="{W}" height="{W}">'
            f'<defs>{defs}</defs><rect width="{W}" height="{W}" fill="{bg}"/>{art}{footer}</svg>')

def _svg_response(svg: str) -> Response:
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=300"})

@api.get("/api/radio/logo.svg")
def api_radio_logo_preview(tpl: str = "", name: str = "", style: str = "", c1: str = "", c2: str = ""):
    t = _TEMPLATE_BY_KEY.get(tpl, {})
    return _svg_response(station_logo_svg(name or t.get("name", "Radio"), style or t.get("style", "plain"),
                                          c1 or t.get("c1", "#e5282a"), c2 or t.get("c2", ""), state["name"]))

@api.get("/api/broadcast/{sid}/logo.svg")
def api_station_logo(sid: str):
    st = _bc_station(sid)
    if not st:
        raise HTTPException(404)
    return _svg_response(station_logo_svg(st["name"], st.get("style", "plain"), st.get("c1"), st.get("c2"),
                                          state["name"]))

# ── Schedule ──
def _mins(hhmm: str) -> int:
    try:
        h, m = str(hhmm).split(":")[:2]
        return (int(h) % 24) * 60 + int(m) % 60
    except Exception:
        return 0

def _block_active(b: dict, now: _dt.datetime) -> bool:
    days = set(b.get("days") or range(7))          # 0 = Monday
    s, e, m, wd = _mins(b.get("start", "00:00")), _mins(b.get("end", "00:00")), now.hour * 60 + now.minute, now.weekday()
    if s == e:
        return wd in days
    if s < e:
        return wd in days and s <= m < e
    return (wd in days and m >= s) or ((wd - 1) % 7 in days and m < e)   # crosses midnight

def _current_program(st: dict, now=None):
    now = now or _dt.datetime.now()
    for b in st.get("blocks") or []:
        if b.get("playlists") and _block_active(b, now):
            return b.get("name") or "Scheduled show", b["playlists"]
    return "Rotation", st.get("rotation") or ["*"]

def _pool(playlists: list, allow_explicit: bool = True) -> list:
    db = get_db()
    q = "SELECT id,path,title,artist,album,duration,cover_id FROM tracks WHERE 1=1"
    p: list = []
    if playlists and "*" not in playlists:
        q += f" AND playlist IN ({','.join('?' * len(playlists))})"
        p = list(playlists)
    if not allow_explicit:
        q += " AND COALESCE(explicit,0)=0"
    rows = [dict(r) for r in db.execute(q, p).fetchall()]
    db.close()
    if not FFMPEG:                                 # without ffmpeg we can only pass MP3 through
        rows = [r for r in rows if r["path"].lower().endswith(".mp3")]
    return rows

# ── Icecast source connection ──
class IcecastError(Exception):
    """slow=True for problems a quick retry won't fix (bad password, mount taken, nothing to play)."""
    def __init__(self, msg, slow=False):
        super().__init__(msg)
        self.slow = slow

def _hdr(v) -> str:
    return re.sub(r"[\r\n]+", " ", str(v or ""))[:200].encode("latin-1", "replace").decode("latin-1")

def _ice_connect(ice: dict, mount: str, st: dict, bitrate: int):
    host, port, tls = ice["host"], int(ice.get("port") or 8000), bool(ice.get("tls"))
    auth = base64.b64encode(f'{ice.get("user") or "source"}:{ice.get("password", "")}'.encode()).decode()
    common = (f"Host: {host}:{port}\r\nAuthorization: Basic {auth}\r\nUser-Agent: leon.music\r\n"
              f"Content-Type: audio/mpeg\r\nIce-Name: {_hdr(st.get('name'))}\r\n"
              f"Ice-Description: {_hdr(st.get('tagline'))}\r\nIce-Genre: {_hdr(st.get('genre') or st.get('name'))}\r\n"
              f"Ice-Public: {1 if ice.get('public') else 0}\r\nIce-Audio-Info: bitrate={bitrate};channels=2;samplerate=44100\r\n")
    last = None
    for method in ("PUT", "SOURCE"):
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except OSError as e:
            raise IcecastError(f"Can't reach Icecast at {host}:{port} ({e.strerror or e})")
        try:
            if tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            req = (f"PUT {mount} HTTP/1.1\r\n{common}Expect: 100-continue\r\n\r\n" if method == "PUT"
                   else f"SOURCE {mount} HTTP/1.0\r\n{common}\r\n")
            sock.sendall(req.encode("latin-1"))
            f = sock.makefile("rb")
            line = f.readline(512).decode("latin-1").split()
            code = int(line[1]) if len(line) > 1 and line[1].isdigit() else 0
            while True:                              # skip response headers
                h = f.readline(2048)
                if h in (b"\r\n", b"\n", b""):
                    break
            if code in (100, 200):
                sock.settimeout(15)
                return sock
            sock.close()
            if code == 401:
                raise IcecastError("Icecast rejected the source username or password", slow=True)
            if code == 403:
                raise IcecastError(f"Mount {mount} is already in use or not allowed", slow=True)
            last = f"Icecast answered {code or 'nothing'}"
        except IcecastError:
            raise
        except (OSError, ssl.SSLError) as e:
            last = f"Connection failed: {e}"
            try: sock.close()
            except Exception: pass
    raise IcecastError(last or "Icecast refused the connection")

def _ice_metadata(ice: dict, mount: str, text: str):
    def _go():
        try:
            scheme = "https" if ice.get("tls") else "http"
            q = _urlencode({"mount": mount, "mode": "updinfo", "song": text, "charset": "UTF-8"})
            auth = base64.b64encode(f'{ice.get("user") or "source"}:{ice.get("password", "")}'.encode()).decode()
            req = urllib.request.Request(f"{scheme}://{ice['host']}:{int(ice.get('port') or 8000)}/admin/metadata?{q}",
                                         headers={"Authorization": f"Basic {auth}", "User-Agent": "leon.music"})
            urllib.request.urlopen(req, timeout=6).read(256)
        except Exception:
            pass
    threading.Thread(target=_go, daemon=True).start()

def _strip_id3(f):
    head = f.read(10)
    if head[:3] == b"ID3" and len(head) == 10:
        size = (head[6] & 0x7f) << 21 | (head[7] & 0x7f) << 14 | (head[8] & 0x7f) << 7 | (head[9] & 0x7f)
        f.seek(10 + size + (10 if head[5] & 0x10 else 0))
        return b""
    return head

class _Caster(threading.Thread):
    LEAD = 3.0                                     # seconds of audio kept ahead of real time

    def __init__(self, sid: str):
        super().__init__(daemon=True, name=f"caster-{sid}")
        self.sid = sid
        self.stop_ev = threading.Event()
        self.proc = None
        self.recent: list = []
        _bc_status[sid] = {"state": "starting", "message": "Starting…", "now": None,
                           "program": None, "since": None, "progress": 5}

    def _set(self, state_, message, **kw):
        s = _bc_status.setdefault(self.sid, {})
        s.update(state=state_, message=message, **kw)

    def stop(self):
        self.stop_ev.set()
        p = self.proc
        if p:
            try: p.kill()
            except Exception: pass

    def run(self):
        backoff = 3
        while not self.stop_ev.is_set():
            cfg = _bc_cfg()
            st = _bc_station(self.sid)
            ice = cfg.get("icecast") or {}
            if not st or not st.get("enabled", True) or not ice.get("host"):
                break
            sock = None
            started = _now()
            try:
                self._set("connecting", "Connecting to Icecast…", progress=30)
                sock = _ice_connect(ice, st["mount"], st, int(cfg.get("bitrate") or 192))
                self._set("buffering", "Encoding the first song…", progress=60)
                self._stream(sock, st, ice, int(cfg.get("bitrate") or 192))
            except IcecastError as e:
                self._set("error", str(e), progress=100)
                if e.slow:
                    backoff = 30
            except Exception as e:
                if not self.stop_ev.is_set():
                    self._set("error", f"Stream interrupted: {e}", progress=100)
            finally:
                if sock:
                    try: sock.close()
                    except Exception: pass
            if _now() - started > 120:
                backoff = 3                          # it was live for a while: retry quickly
            if self.stop_ev.wait(backoff):
                break
            backoff = min(backoff * 2, 60)
        self._set("stopped", "Off air", now=None, progress=0)

    def _next_track(self, st):
        program, playlists = _current_program(st)
        clean = st.get("explicit", True) is False
        pool = _pool(playlists, not clean)
        if not pool and playlists != ["*"]:
            pool = _pool(["*"], not clean)           # scheduled playlist empty: fall back to library
        if not pool:
            raise IcecastError("No playable songs in this station's playlists", slow=True)
        recent = set(self.recent[-min(len(pool) - 1, 50):]) if len(pool) > 1 else set()
        choices = [t for t in pool if t["id"] not in recent] or pool
        t = _random.choice(choices)
        self.recent.append(t["id"])
        self.recent = self.recent[-200:]
        return program, t

    def _stream(self, sock, st, ice, bitrate):
        byterate = bitrate * 125                     # bytes per second at CBR
        wall0, media, fails, went_live = _now(), 0.0, 0, False
        while not self.stop_ev.is_set():
            st = _bc_station(self.sid) or st          # pick up schedule edits between songs
            program, t = self._next_track(st)
            path = Path(t["path"])
            sent = 0
            try:
                if FFMPEG:
                    self.proc = _subprocess.Popen(
                        [FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", "-i", str(path),
                         "-vn", "-map", "0:a:0", "-ac", "2", "-ar", "44100", "-c:a", "libmp3lame",
                         "-b:a", f"{bitrate}k", "-write_xing", "0", "-id3v2_version", "0", "-f", "mp3", "-"],
                        stdout=_subprocess.PIPE, stderr=_subprocess.DEVNULL, creationflags=_NO_WINDOW)
                    src, rate = self.proc.stdout, byterate
                else:
                    src = open(path, "rb")
                    pre = _strip_id3(src)
                    size = path.stat().st_size
                    rate = max(8000, size / max(t["duration"] or 1, 1))
                    if pre:
                        sock.sendall(pre); sent += len(pre); media += len(pre) / rate
                title = f'{t["artist"] or "Unknown"} - {t["title"] or path.stem}'
                announced = False
                while not self.stop_ev.is_set():
                    chunk = src.read(8192)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    sent += len(chunk)
                    media += len(chunk) / rate
                    if not announced:
                        announced = True
                        _ice_metadata(ice, st["mount"], title)
                        self._set("live", "On air", progress=100, program=program,
                                  now={"title": t["title"], "artist": t["artist"], "album": t["album"],
                                       "cover_id": t["cover_id"], "track_id": t["id"],
                                       "duration": t["duration"], "started": _now()})
                        if not went_live:
                            went_live = True
                            _bc_status[self.sid]["since"] = _now()
                    behind = (_now() - wall0) - media
                    if behind > 10:                   # stalled (e.g. slow disk): don't burst, re-sync clock
                        wall0 = _now() - media
                    ahead = media - (_now() - wall0) - self.LEAD
                    if ahead > 0 and self.stop_ev.wait(ahead):
                        break
                src.close()
            finally:
                if self.proc:
                    try: self.proc.kill(); self.proc.wait(timeout=3)
                    except Exception: pass
                    self.proc = None
            fails = 0 if sent > 16384 else fails + 1
            if fails >= 6:
                raise IcecastError("Couldn't encode any songs (check the files and ffmpeg)", slow=True)

def bc_sync():
    """Start enabled stations that aren't running; stop ones that were removed or disabled."""
    cfg = _bc_cfg()
    want = {s["id"] for s in cfg.get("stations", [])
            if s.get("enabled", True) and cfg.get("live") and (cfg.get("icecast") or {}).get("host")}
    with _casters_lock:
        for sid in list(_casters):
            if sid not in want or not _casters[sid].is_alive():
                _casters.pop(sid).stop()
        for sid in want:
            if sid not in _casters:
                c = _Caster(sid)
                _casters[sid] = c
                c.start()
    for sid in list(_bc_status):
        if sid not in want and sid not in _casters:
            _bc_status[sid].update(state="stopped", message="Off air", now=None)

@api.on_event("startup")
def _bc_autostart():
    threading.Thread(target=bc_sync, daemon=True).start()

def _public_base(ice: dict) -> str:
    if ice.get("public_url"):
        return ice["public_url"].rstrip("/")
    return f'{"https" if ice.get("tls") else "http"}://{ice.get("host")}:{int(ice.get("port") or 8000)}'

def _is_loopback(url: str) -> bool:
    h = (urlparse(url).hostname or "").lower()
    return h in ("localhost", "::1") or h.startswith("127.")

def _public_station(st: dict, ice: dict) -> dict:
    url = _public_base(ice) + st["mount"]
    s = _bc_status.get(st["id"], {})
    return {"id": "live-" + st["id"], "sid": st["id"], "live": True, "name": st["name"],
            "tagline": st.get("tagline", ""), "genre": st.get("tagline", ""), "url": url,
            "relay": _is_loopback(url), "logo": f"/api/broadcast/{st['id']}/logo.svg?v={st.get('rev', 0)}",
            "c1": st.get("c1"), "c2": st.get("c2"), "template": st.get("template", ""),
            "explicit": st.get("explicit", True) is not False,
            "rotation": st.get("rotation") or ["*"], "blocks": st.get("blocks") or [],
            "state": s.get("state", "stopped"), "now": s.get("now"), "program": s.get("program")}

def _live_stations() -> list:
    cfg = _bc_cfg()
    if not cfg.get("live"):
        return []
    ice = cfg.get("icecast") or {}
    return [_public_station(s, ice) for s in cfg.get("stations", [])]

# ── Broadcast API ──
_SLUG = re.compile(r"[^a-z0-9]+")

@api.get("/api/broadcast/templates")
def api_bc_templates():
    return {"templates": STATION_TEMPLATES, "ffmpeg": bool(FFMPEG)}

@api.get("/api/broadcast")
def api_bc_get(req: Request):
    _require_admin(req)
    cfg = _bc_cfg()
    ice = dict(cfg.get("icecast") or {})
    ice["has_password"] = bool(ice.pop("password", ""))
    return {"live": bool(cfg.get("live")), "bitrate": cfg.get("bitrate", 192), "icecast": ice,
            "stations": cfg.get("stations", []), "ffmpeg": bool(FFMPEG)}

@api.get("/api/broadcast/status")
def api_bc_status(req: Request):
    admin = _is_admin(req)
    out = {}
    for sid, s in _bc_status.items():
        d = {k: s.get(k) for k in ("state", "now", "program", "since", "progress")}
        d["message"] = s.get("message") if (admin or s.get("state") != "error") else "Temporarily off air"
        out[sid] = d
    return out

def _clean_ice(raw: dict, old: dict) -> dict:
    host = (raw.get("host") or "").strip()
    host = re.sub(r"^[a-z]+://", "", host, flags=re.I).split("/")[0]
    if ":" in host and not host.startswith("["):
        host, _, p = host.partition(":")
        raw.setdefault("port", p)
    if not host or not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", host):
        raise HTTPException(400, "Enter the Icecast server's host name or IP")
    try:
        port = int(raw.get("port") or 8000)
        assert 0 < port < 65536
    except Exception:
        raise HTTPException(400, "Port must be a number between 1 and 65535")
    pw = raw.get("password") or old.get("password") or ""
    if not pw:
        raise HTTPException(400, "Enter the Icecast source password")
    pub = (raw.get("public_url") or "").strip()
    if pub and not pub.startswith(("http://", "https://")):
        raise HTTPException(400, "Public URL must start with http:// or https://")
    return {"host": host, "port": port, "tls": bool(raw.get("tls")), "user": (raw.get("user") or "source").strip()[:60],
            "password": pw, "public_url": pub, "public": bool(raw.get("public")),
            "mount_prefix": _SLUG.sub("-", (raw.get("mount_prefix") or "").lower()).strip("-")[:30]}

@api.post("/api/broadcast/test")
async def api_bc_test(req: Request):
    _require_admin(req)
    body = await req.json()
    ice = _clean_ice(body, (_bc_cfg().get("icecast") or {}))
    result = {"reachable": False, "icecast": False, "auth": False, "message": ""}
    def _probe():
        try:
            scheme = "https" if ice["tls"] else "http"
            d = json.loads(_fetch_bytes(f"{scheme}://{ice['host']}:{ice['port']}/status-json.xsl", timeout=6))
            result["reachable"] = True
            result["icecast"] = "icestats" in d
            result["server"] = (d.get("icestats") or {}).get("server_id", "")
        except Exception:
            pass
        mount = "/leonmusic-test-" + secrets.token_hex(3)
        try:
            sock = _ice_connect(ice, mount, {"name": "leon.music connection test"}, 128)
            sock.close()
            result["reachable"] = result["auth"] = True
            result["message"] = "Connected — Icecast accepted the source password."
        except IcecastError as e:
            result["message"] = str(e)
    await run_in_threadpool(_probe)
    return result

@api.post("/api/broadcast")
async def api_bc_save(req: Request):
    """Save the whole setup from the wizard and (re)start the stations."""
    _require_admin(req)
    body = await req.json()
    cfg_all = load_config()
    old = cfg_all.get("broadcast") or {}
    ice = _clean_ice(dict(body.get("icecast") or {}), old.get("icecast") or {})
    bitrate = int(body.get("bitrate") or 192)
    if bitrate not in (96, 128, 160, 192, 256, 320):
        bitrate = 192
    old_by_id = {s["id"]: s for s in old.get("stations", [])}
    stations, mounts = [], set()
    for raw in (body.get("stations") or [])[:12]:
        name = (raw.get("name") or "").strip()[:40]
        if not name:
            raise HTTPException(400, "Every station needs a name")
        sid = raw.get("id") if raw.get("id") in old_by_id else secrets.token_hex(4)
        tpl = _TEMPLATE_BY_KEY.get(raw.get("template") or "")
        slug = _SLUG.sub("-", (tpl["key"] if tpl and name == tpl["name"] else name).lower()).strip("-") or sid
        mount = "/" + "-".join(x for x in (ice["mount_prefix"], slug) if x)
        while mount in mounts:
            mount += "-2"
        mounts.add(mount)
        def _pl(v):
            return [str(x)[:120] for x in (v or []) if isinstance(x, str)][:50]
        blocks = []
        for b in (raw.get("blocks") or [])[:24]:
            if not _pl(b.get("playlists")):
                continue
            blocks.append({"name": (b.get("name") or "Show").strip()[:40],
                           "days": sorted({int(d) for d in (b.get("days") or range(7)) if str(d).isdigit() and 0 <= int(d) < 7}),
                           "start": f"{_mins(b.get('start', '00:00')) // 60:02d}:{_mins(b.get('start', '00:00')) % 60:02d}",
                           "end": f"{_mins(b.get('end', '00:00')) // 60:02d}:{_mins(b.get('end', '00:00')) % 60:02d}",
                           "playlists": _pl(b.get("playlists")),
                           "cover": b["cover"] if isinstance(b.get("cover"), str) and len(b["cover"]) < 300000
                                    and b["cover"].startswith("data:image/jpeg;base64,") else ""})
        prev = old_by_id.get(sid, {})
        if tpl and tpl.get("single"):               # holiday station: exactly one playlist, no shows
            one = [x for x in _pl(raw.get("rotation")) if x != "*"][:1]
            if not one:
                raise HTTPException(400, f"{name}: pick your Christmas playlist")
            raw["rotation"], blocks = one, []
        stations.append({
            "id": sid, "name": name, "template": tpl["key"] if tpl else "",
            "tagline": (raw.get("tagline") or (tpl or {}).get("tagline") or "").strip()[:90],
            "style": raw.get("style") if raw.get("style") in {t["style"] for t in STATION_TEMPLATES} | {"plain"}
                     else (tpl or {}).get("style", "plain"),
            "c1": _clean_color(raw.get("c1")) or (tpl or {}).get("c1", "#e5282a"),
            "c2": _clean_color(raw.get("c2")) or (tpl or {}).get("c2", "#ff7a1a"),
            "mount": mount, "enabled": raw.get("enabled", True) is not False,
            "explicit": raw.get("explicit", True) is not False,
            "rotation": _pl(raw.get("rotation")) or ["*"], "blocks": blocks,
            "rev": int(prev.get("rev", 0)) + 1})
    cfg_all["broadcast"] = {"live": bool(stations) and body.get("live", True) is not False,
                            "bitrate": bitrate, "icecast": ice, "stations": stations}
    save_config(cfg_all)
    # Restart casters whose mount/stream settings changed; schedule edits apply live between songs
    with _casters_lock:
        for sid, c in list(_casters.items()):
            p = old_by_id.get(sid, {})
            n = next((s for s in stations if s["id"] == sid), None)
            if (not n or n["mount"] != p.get("mount") or n["name"] != p.get("name")
                    or ice != (old.get("icecast") or {}) or bitrate != old.get("bitrate")):
                _casters.pop(sid).stop()
    for s in stations:
        _bc_status[s["id"]] = {"state": "starting", "message": "Saved — starting…", "now": None,
                               "program": None, "since": None, "progress": 10} \
            if s["id"] not in _casters else _bc_status.get(s["id"], {})
    threading.Thread(target=bc_sync, daemon=True).start()
    return api_bc_get(req)

@api.post("/api/broadcast/{sid}/{action}")
def api_bc_toggle(sid: str, action: str, req: Request):
    _require_admin(req)
    if action not in ("start", "stop"):
        raise HTTPException(404)
    c = load_config()
    b = c.get("broadcast") or {}
    st = next((s for s in b.get("stations", []) if s["id"] == sid), None)
    if not st:
        raise HTTPException(404)
    st["enabled"] = action == "start"
    if action == "start":
        b["live"] = True
    save_config(c)
    bc_sync()
    return {"status": "ok", "enabled": st["enabled"]}

# ── Artist photos ─────────────────────────────────────────────────────────────
_pic_sem   = threading.Semaphore(4)       # at most 4 Deezer lookups at once
_pic_locks: dict = {}
_NO_PIC    = {"unknown artist", "various artists"}

def _pic_paths(name: str):
    k = hashlib.sha1(name.strip().lower().encode("utf-8")).hexdigest()[:20]
    return ARTIST_PICS_DIR / f"{k}.jpg", ARTIST_PICS_DIR / f"{k}.none"

def _square_jpeg(data: bytes, size: int = 600) -> bytes:
    img = Image.open(io.BytesIO(data)).convert("RGB")
    w, h = img.size
    s = min(w, h)
    left, top = (w - s) // 2, (h - s) // 2
    img = img.crop((left, top, left + s, top + s)).resize((size, size), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=88)
    return out.getvalue()

def _deezer_artist_pic(name: str):
    """Exact (case-insensitive) name match only, so we don't show the wrong band."""
    raw = _fetch_bytes(f"https://api.deezer.com/search/artist?q={quote(name)}&limit=10")
    data = json.loads(raw.decode("utf-8", "replace"))
    want = name.strip().lower()
    matches = [a for a in data.get("data", [])
               if (a.get("name") or "").strip().lower() == want
               and a.get("picture_xl") and "/artist//" not in a["picture_xl"]]   # '/artist//' = placeholder
    if not matches:
        return None
    best = max(matches, key=lambda a: a.get("nb_fan") or 0)
    return _square_jpeg(_fetch_bytes(best["picture_xl"], timeout=10, limit=5_000_000))

def _pic_response(req: Request, jpg: Path) -> Response:
    """Serve a stored photo with an ETag. 'no-cache' makes the browser re-check every time (a cheap 304
    when nothing changed), so a photo the admin just replaced is never hidden behind a stale cached copy."""
    st = jpg.stat()
    etag = f'"{st.st_mtime_ns:x}-{st.st_size:x}"'
    headers = {"Cache-Control": "no-cache", "ETag": etag}
    if req.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(jpg.read_bytes(), media_type="image/jpeg", headers=headers)

@api.get("/api/artist/pic")
def api_artist_pic(name: str, req: Request):
    name = name.strip()
    if not name or name.lower() in _NO_PIC:
        raise HTTPException(404)
    jpg, none = _pic_paths(name)
    if jpg.exists():
        return _pic_response(req, jpg)
    if not state["artist_pics_online"]:
        raise HTTPException(404)
    if none.exists() and _now() - none.stat().st_mtime < 7 * 86400:
        raise HTTPException(404)                      # looked recently, nothing found
    with _pic_locks.setdefault(jpg.name, threading.Lock()):
        if jpg.exists():                              # another request finished first
            return _pic_response(req, jpg)
        data, failed = None, False
        with _pic_sem:
            try:
                data = _deezer_artist_pic(name)
            except Exception:
                failed = True                         # network error: don't remember as "none"
        if data:
            jpg.write_bytes(data)
            return _pic_response(req, jpg)
        if not failed:
            none.write_bytes(b"")
    raise HTTPException(404)

@api.post("/api/artist/pic")
async def api_artist_pic_set(req: Request):
    _require_admin(req)
    body = await req.json()
    name = (body.get("name") or "").strip()
    url  = (body.get("image_url") or "").strip()
    if not name:
        raise HTTPException(400, "name required")
    jpg, none = _pic_paths(name)
    if not url:                                       # reset to automatic
        jpg.unlink(missing_ok=True)
        none.unlink(missing_ok=True)
        return {"status": "reset"}
    if _clean_url(url) is None:
        raise HTTPException(400, "Image URL must start with http:// or https://")
    try:
        data = await run_in_threadpool(_fetch_bytes, url, 10, 10_000_000)
    except Exception as e:
        raise HTTPException(400, f"Could not download image: {e}")
    try:
        jpg.write_bytes(_square_jpeg(data))
    except Exception:
        raise HTTPException(400, "That URL is not a valid image")
    none.unlink(missing_ok=True)
    return {"status": "ok"}

# ── Tracks By Year ────────────────────────────────────────────────────────────
YEAR_COVERS_DIR = Path.home() / ".leon-music" / "year-covers"
YEAR_COVERS_DIR.mkdir(parents=True, exist_ok=True)

# year-scan state (separate from library scan)
_year_scan: dict = {"running": False, "done": 0, "total": 0, "found": 0}

def _deezer_lookup_year(artist: str, title: str) -> Optional[int]:
    """Hit Deezer search API; return release year or None."""
    try:
        from urllib.parse import quote as _q
        url = f'https://api.deezer.com/search?q=artist:"{_q(artist)}" track:"{_q(title)}"&limit=1'
        req = urllib.request.Request(url, headers={"User-Agent": "leon.music/1"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=6) as r:
            data = json.loads(r.read())
        rd = (data.get("data") or [{}])[0].get("release_date") or ""
        yr = rd[:4]
        return int(yr) if yr.isdigit() and 1900 <= int(yr) <= 2100 else None
    except Exception:
        return None

def _run_year_scan():
    """Enrich tracks that have no year by querying Deezer."""
    global _year_scan
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, artist, title FROM tracks WHERE year IS NULL OR year = 0"
        ).fetchall()
        _year_scan["total"] = len(rows)
        _year_scan["done"]  = 0
        _year_scan["found"] = 0
        for row in rows:
            if not _year_scan["running"]:
                break
            yr = _deezer_lookup_year(row["artist"] or "", row["title"] or "")
            if yr:
                db.execute("UPDATE tracks SET year=? WHERE id=?", (yr, row["id"]))
                db.commit()
                _year_scan["found"] += 1
            _year_scan["done"] += 1
        db.commit()
    finally:
        db.close()
        _year_scan["running"] = False

def _make_year_cover(year: int, artist: str) -> bytes:
    """Generate a 600×600 JPEG cover for a year group."""
    import random, hashlib as _hsh
    seed = int(_hsh.md5(str(year).encode()).hexdigest(), 16)
    rng  = random.Random(seed)
    # palette: dark base + two accent colours derived from year
    def _hue(h, s=0.6, v=0.5):
        import colorsys
        r, g, b = colorsys.hsv_to_rgb(h % 1.0, s, v)
        return (int(r*255), int(g*255), int(b*255))
    base_h = rng.random()
    c1 = _hue(base_h, .65, .35)
    c2 = _hue(base_h + .12, .55, .22)
    c3 = _hue(base_h + .55, .70, .55)  # accent

    SZ = 600
    img = Image.new("RGB", (SZ, SZ), c1)
    draw = ImageDraw.Draw(img)

    # Draw abstract background stripes/shapes
    for _ in range(rng.randint(6, 12)):
        x = rng.randint(-SZ//4, SZ)
        y = rng.randint(-SZ//4, SZ)
        r = rng.randint(SZ//6, SZ//2)
        col = c2 if rng.random() > .5 else _hue(base_h + rng.uniform(-.1, .25), .45, .28)
        draw.ellipse([x, y, x+r*2, y+r*2], fill=col)

    # Dark gradient overlay (bottom-heavy)
    overlay = Image.new("RGBA", (SZ, SZ), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    for i in range(SZ):
        alpha = int(80 + 130 * (i / SZ) ** 1.6)
        od.line([(0, i), (SZ, i)], fill=(0, 0, 0, alpha))
    img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
    draw = ImageDraw.Draw(img)

    # Accent stripe on left edge
    draw.rectangle([0, 0, 6, SZ], fill=c3)

    # Year text – large, top-left
    font_big = None
    for fname in ["arialbd.ttf","Arial Bold.ttf","DejaVuSans-Bold.ttf",
                  "LiberationSans-Bold.ttf","FreeSansBold.ttf"]:
        try:
            font_big = ImageFont.truetype(fname, 140)
            break
        except Exception:
            pass
    if font_big is None:
        try: font_big = ImageFont.load_default(size=80)
        except Exception: font_big = ImageFont.load_default()

    font_sm = None
    for fname in ["arial.ttf","Arial.ttf","DejaVuSans.ttf","LiberationSans-Regular.ttf","FreeSans.ttf"]:
        try:
            font_sm = ImageFont.truetype(fname, 36)
            break
        except Exception:
            pass
    if font_sm is None:
        try: font_sm = ImageFont.load_default(size=36)
        except Exception: font_sm = ImageFont.load_default()

    yr_str = str(year)
    draw.text((38, 28), yr_str, fill="#ffffff", font=font_big)

    # Artist name – bottom left
    if artist:
        artist_disp = artist[:40] + ("…" if len(artist) > 40 else "")
        draw.text((38, SZ - 80), artist_disp, fill=(220, 220, 220), font=font_sm)

    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88, optimize=True)
    return buf.getvalue()

@api.get("/api/years")
def api_years():
    """Return list of years with track counts and a random artist."""
    db = get_db()
    rows = db.execute("""
        SELECT year, COUNT(*) as track_count
        FROM tracks
        WHERE year IS NOT NULL AND year > 0
        GROUP BY year
        ORDER BY year DESC
    """).fetchall()
    result = []
    for row in rows:
        yr = row["year"]
        # Pick random artist for this year
        artists = db.execute(
            "SELECT DISTINCT COALESCE(album_artist, artist) FROM tracks WHERE year=? LIMIT 50",
            (yr,)
        ).fetchall()
        artist = ""
        if artists:
            import random as _rnd
            artist = (_rnd.choice(artists)[0] or "").strip()
        result.append({"year": yr, "track_count": row["track_count"], "artist": artist})
    db.close()
    return result

@api.post("/api/years/scan")
def api_years_scan_start(req: Request):
    """Start year-enrichment scan (Deezer lookups for tracks missing year). Admin only."""
    _require_admin(req)
    if _year_scan["running"]:
        return {"status": "already_running", **_year_scan}
    _year_scan["running"] = True
    threading.Thread(target=_run_year_scan, daemon=True).start()
    return {"status": "started"}

@api.get("/api/years/scan/status")
def api_years_scan_status():
    db = get_db()
    missing = db.execute("SELECT COUNT(*) FROM tracks WHERE year IS NULL OR year<=0").fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM tracks").fetchone()[0]
    db.close()
    return {**_year_scan, "missing": missing, "library": total}

@api.get("/api/years/{year}/cover")
def api_year_cover(year: int):
    """Return (or generate) the cover JPEG for a year group."""
    out = YEAR_COVERS_DIR / f"{year}.jpg"
    if not out.exists():
        db = get_db()
        artists = db.execute(
            "SELECT DISTINCT COALESCE(album_artist, artist) as a FROM tracks WHERE year=? LIMIT 50",
            (year,)
        ).fetchall()
        db.close()
        import random as _rnd
        artist = (_rnd.choice(artists)[0] or "") if artists else ""
        data = _make_year_cover(year, artist)
        out.write_bytes(data)
    return Response(content=out.read_bytes(), media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=86400"})

@api.delete("/api/years/{year}/cover")
def api_year_cover_reset(year: int):
    """Force regenerate the cover (delete cached one)."""
    out = YEAR_COVERS_DIR / f"{year}.jpg"
    out.unlink(missing_ok=True)
    return {"status": "ok"}

# ── Charts (play counts) ──────────────────────────────────────────────────────
CHART_PERIODS = {"week": 7 * 86400, "month": 30 * 86400, "all": None}
_PLAY_DEDUPE_SECS = 30          # ignore the same listener re-logging a track this fast

def _listener_id(req: Request) -> str:
    host = (req.client.host if req.client else "") or ""
    return hashlib.sha1(f"leon.music:{host}".encode()).hexdigest()[:12]

@api.post("/api/plays/{track_id}")
def api_play_log(track_id: int, req: Request):
    """Called by the player once a track has been listened to for a while."""
    listener = _listener_id(req)
    now = _now()
    db = get_db()
    try:
        if not db.execute("SELECT 1 FROM tracks WHERE id=?", (track_id,)).fetchone():
            raise HTTPException(404)
        dup = db.execute(
            "SELECT 1 FROM plays WHERE track_id=? AND listener=? AND played_at>?",
            (track_id, listener, now - _PLAY_DEDUPE_SECS)).fetchone()
        if not dup:
            su = _session_user(req)
            db.execute("INSERT INTO plays(track_id,listener,played_at,user_id) VALUES(?,?,?,?)",
                       (track_id, listener, now, su["id"] if su and su["id"] else None))
            db.commit()
    finally:
        db.close()
    return {"status": "ok", "counted": not dup}

def _genre_parts(raw) -> tuple:
    """'Hip-Hop/Rap' -> ('hiphop', 'Hip-Hop'); ignores ID3 numeric junk like '(13)'."""
    if not raw:
        return None, None
    first = re.split(r"[;/,|]", str(raw))[0].strip()
    first = re.sub(r"^\(\d+\)\s*", "", first).strip()
    key = re.sub(r"[^a-z0-9&]", "", first.lower())
    if not key or key.isdigit():
        return None, None
    return key, first

def _play_counts(db, start, end) -> dict:
    q = "SELECT track_id, COUNT(*) AS n, COUNT(DISTINCT listener) AS l FROM plays WHERE played_at<?"
    p: list = [end]
    if start is not None:
        q += " AND played_at>=?"; p.append(start)
    q += " GROUP BY track_id"
    return {r["track_id"]: (r["n"], r["l"]) for r in db.execute(q, p).fetchall()}

def _ranked(ids, counts: dict, info: dict) -> list:
    """Sort ids by plays, then unique listeners, then title (stable, deterministic)."""
    return sorted(ids, key=lambda i: (-counts[i][0], -counts[i][1],
                                      (info.get(i, {}).get("title") or "").lower()))

@api.get("/api/charts")
def api_charts(period: str = "week"):
    if period not in CHART_PERIODS:
        raise HTTPException(400, "period must be week, month or all")
    span = CHART_PERIODS[period]
    now = _now()
    db = get_db()
    cur  = _play_counts(db, now - span if span else None, now + 1)
    prev = _play_counts(db, now - 2 * span, now - span) if span else {}
    ids = set(cur) | set(prev)
    info: dict = {}
    if ids:
        ph = ",".join("?" * len(ids))
        for r in db.execute(f"""SELECT id,title,artist,album,duration,cover_id,genre,
                                       COALESCE(album_artist,artist) AS main_artist
                                FROM tracks WHERE id IN ({ph})""", list(ids)).fetchall():
            info[r["id"]] = dict(r)
    total_plays = sum(n for n, _ in cur.values())
    listeners = db.execute(
        "SELECT COUNT(DISTINCT listener) FROM plays WHERE played_at>=?",
        (now - span if span else 0,)).fetchone()[0]
    db.close()

    # Drop plays whose track was removed from the library
    cur  = {i: v for i, v in cur.items() if i in info}
    prev = {i: v for i, v in prev.items() if i in info}

    def track_chart(chart_id, title, subtitle, cur_ids, prev_ids, limit):
        order = _ranked(cur_ids, cur, info)[:limit]
        prev_rank = {t: n + 1 for n, t in enumerate(_ranked(prev_ids, prev, info))}
        tracks = []
        for n, tid in enumerate(order):
            t = {k: v for k, v in info[tid].items() if k != "main_artist"}
            t.update(rank=n + 1, plays=cur[tid][0], listeners=cur[tid][1],
                     prev_rank=prev_rank.get(tid), is_new=bool(span) and tid not in prev_rank)
            tracks.append(t)
        return {"id": chart_id, "title": title, "subtitle": subtitle,
                "plays": sum(cur[t][0] for t in cur_ids), "tracks": tracks}

    charts = []
    if cur:
        charts.append(track_chart("top", "Top 50", "The most played songs on the server",
                                  list(cur), list(prev), 50))

    # Genre charts
    g_label: dict = {}
    g_cur: dict = {}
    g_prev: dict = {}
    for tid, t in info.items():
        key, label = _genre_parts(t.get("genre"))
        if not key:
            continue
        g_label.setdefault(key, {}).setdefault(label, 0)
        g_label[key][label] += 1
        if tid in cur:  g_cur.setdefault(key, []).append(tid)
        if tid in prev: g_prev.setdefault(key, []).append(tid)
    genre_charts = []
    for key, tids in g_cur.items():
        if len(tids) < 3:
            continue
        label = max(g_label[key].items(), key=lambda kv: kv[1])[0]
        genre_charts.append(track_chart(f"genre:{key}", f"Top {label}", f"Most played {label} songs",
                                        tids, g_prev.get(key, []), 25))
    genre_charts.sort(key=lambda c: -c["plays"])
    charts += genre_charts[:12]

    # Artist chart (+ each artist's own top songs)
    def artist_totals(counts):
        tot: dict = {}
        for tid, (n, l) in counts.items():
            a = (info[tid].get("main_artist") or "Unknown").strip() or "Unknown"
            s = tot.setdefault(a, [0, 0, []])
            s[0] += n; s[1] += l; s[2].append(tid)
        return tot
    a_cur, a_prev = artist_totals(cur), artist_totals(prev)
    a_order = sorted(a_cur, key=lambda a: (-a_cur[a][0], -a_cur[a][1], a.lower()))
    a_prev_rank = {a: n + 1 for n, a in enumerate(
        sorted(a_prev, key=lambda a: (-a_prev[a][0], -a_prev[a][1], a.lower())))}
    artists = []
    for n, a in enumerate(a_order[:20]):
        chart = track_chart(f"artist:{a}", a, f"{a}'s most played songs",
                            a_cur[a][2], a_prev.get(a, [0, 0, []])[2], 25)
        top = chart["tracks"][0] if chart["tracks"] else {}
        artists.append({"name": a, "rank": n + 1, "plays": a_cur[a][0],
                        "prev_rank": a_prev_rank.get(a),
                        "is_new": bool(span) and a not in a_prev_rank,
                        "cover_id": top.get("cover_id"), "chart": chart})

    return {"period": period, "total_plays": total_plays, "listeners": listeners,
            "charts": charts, "artists": artists}

# ── New page ──────────────────────────────────────────────────────────────────
_NEW_WINDOW_DAYS = 14         # a playlist counts as new/updated if songs were added this recently
_TRACK_COLS = "id,title,artist,album,track_num,disc_num,year,duration,cover_id,playlist"

@api.get("/api/new")
def api_new():
    """Everything the New page shows, in one request."""
    import datetime as _dt
    db = get_db()
    # Newest first: when the server first saw the file, then the file's own modified time
    # (the first scan gives every track the same added_at, so mtime breaks the tie).
    songs = [dict(r) for r in db.execute(f"""
        SELECT {_TRACK_COLS}, added_at FROM tracks
        ORDER BY added_at DESC, mtime DESC LIMIT 100""").fetchall()]

    albums = [dict(r) for r in db.execute("""
        SELECT album, COALESCE(album_artist,artist) AS artist, MAX(year) AS year,
               COUNT(*) AS track_count, SUM(duration) AS total_duration,
               MIN(cover_id) AS cover_id, MAX(added_at) AS added_at
        FROM tracks WHERE album IS NOT NULL AND album<>''
        GROUP BY album ORDER BY MAX(added_at) DESC, MAX(mtime) DESC LIMIT 18""").fetchall()]

    cutoff = (_dt.datetime.utcnow() - _dt.timedelta(days=_NEW_WINDOW_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    playlists = []
    for r in db.execute("""
        SELECT playlist AS name, COUNT(*) AS track_count, SUM(duration) AS total_duration,
               MIN(added_at) AS first_added, MAX(added_at) AS last_added,
               SUM(CASE WHEN added_at>=? THEN 1 ELSE 0 END) AS recent,
               MAX(mtime) AS last_mtime
        FROM tracks WHERE playlist IS NOT NULL
        GROUP BY playlist ORDER BY MAX(added_at) DESC, MAX(mtime) DESC""", (cutoff,)).fetchall():
        d = dict(r)
        d["display_name"] = state["playlist_names"].get(d["name"], d["name"])
        d["status"] = ("new" if d["first_added"] >= cutoff else
                       "updated" if d["recent"] else "")
        d["covers"] = [c[0] for c in db.execute(
            """SELECT cover_id FROM tracks WHERE playlist=? AND cover_id IS NOT NULL
               GROUP BY cover_id ORDER BY MAX(added_at) DESC LIMIT 4""", (d["name"],)).fetchall()]
        d["has_cover"] = (COVERS_DIR / f"{_safe_name(d['name'])}.jpg").exists()
        playlists.append(d)

    this_year = _dt.date.today().year
    fresh = [dict(r) for r in db.execute("""
        SELECT album, COALESCE(album_artist,artist) AS artist, MAX(year) AS year,
               COUNT(*) AS track_count, SUM(duration) AS total_duration, MIN(cover_id) AS cover_id
        FROM tracks WHERE year>=? AND album IS NOT NULL AND album<>''
        GROUP BY album ORDER BY MAX(year) DESC, MAX(added_at) DESC LIMIT 18""",
        (this_year - 1,)).fetchall()]

    new_artists = [dict(r) for r in db.execute("""
        SELECT COALESCE(album_artist,artist) AS name, COUNT(DISTINCT album) AS album_count,
               COUNT(*) AS track_count, MIN(cover_id) AS cover_id, MIN(added_at) AS first_added
        FROM tracks GROUP BY name HAVING name IS NOT NULL AND name<>''
        ORDER BY MIN(added_at) DESC, MAX(mtime) DESC LIMIT 12""").fetchall()]
    db.close()

    # Trending = this week's chart, biggest climbers and new entries first
    week = api_charts("week")
    top = week["charts"][0] if week["charts"] else None
    trending = []
    if top:
        def heat(t):
            climb = (t["prev_rank"] - t["rank"]) if t["prev_rank"] else 0
            return (-(t["is_new"] or climb > 0), -t["plays"], -climb)
        trending = sorted(top["tracks"], key=heat)[:16]

    return {"songs": songs, "albums": albums, "playlists": playlists, "fresh": fresh,
            "fresh_year": this_year - 1, "artists": new_artists, "trending": trending,
            "top_chart": ({"id": top["id"], "title": top["title"], "plays": top["plays"],
                           "tracks": top["tracks"][:50]} if top else None)}

# ── Chart cover art ───────────────────────────────────────────────────────────
_PERIOD_LABEL = {"week": "THIS WEEK", "month": "THIS MONTH", "all": "ALL TIME"}
_chart_cover_cache: dict = {}          # (chart_id, period, top_id, accent) -> jpeg bytes
_charts_memo: dict = {}                # period -> (computed_at, api_charts result)

def _font(names, size):
    for n in names:
        try: return ImageFont.truetype(n, size)
        except Exception: pass
    try: return ImageFont.load_default(size=size)
    except Exception: return ImageFont.load_default()

_BLACK = ["ariblk.ttf", "Arial Black.ttf", "arialbd.ttf", "Arial Bold.ttf",
          "DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]
_BOLD  = ["arialbd.ttf", "Arial Bold.ttf", "DejaVuSans-Bold.ttf",
          "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]

def _chart_rgb(chart_id: str):
    import colorsys
    if chart_id == "top":
        h = (_clean_color(state.get("accent")) or "#e5282a").lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
    hue = int(hashlib.md5(chart_id.encode()).hexdigest()[:6], 16) / 0xFFFFFF
    r, g, b = colorsys.hsv_to_rgb(hue, .72, .85)
    return int(r*255), int(g*255), int(b*255)

def _fit_text(draw, text, names, max_w, start, minimum):
    size = start
    while size > minimum:
        f = _font(names, size)
        if draw.textlength(text, font=f) <= max_w:
            return f
        size -= 6
    return _font(names, minimum)

def _ellipsize(draw, text, font, max_w):
    if draw.textlength(text, font=font) <= max_w:
        return text
    while text and draw.textlength(text + "…", font=font) > max_w:
        text = text[:-1]
    return text.rstrip() + "…"

def _make_chart_cover(chart: dict, period: str, artist_pic: Optional[bytes]) -> bytes:
    from PIL import ImageOps, ImageFilter
    SZ, M = 600, 40
    rgb = _chart_rgb(chart["id"])
    dark  = tuple(int(c * .18) for c in rgb)
    light = tuple(min(255, int(c + (255 - c) * .45)) for c in rgb)

    # Background: #1 song's cover (or the artist photo) as a duotone in the chart colour
    src = artist_pic
    if not src and chart["tracks"] and chart["tracks"][0].get("cover_id"):
        db = get_db()
        row = db.execute("SELECT data FROM covers WHERE id=?",
                         (chart["tracks"][0]["cover_id"],)).fetchone()
        db.close()
        src = row["data"] if row else None
    bg = None
    if src:
        try:
            bg = ImageOps.fit(Image.open(io.BytesIO(src)).convert("L"), (SZ, SZ))
            bg = ImageOps.autocontrast(bg, cutoff=2)
            bg = ImageOps.colorize(bg, black=dark, white=light).convert("RGBA")
        except Exception:
            bg = None
    if bg is None:                                   # no art: soft colour blobs
        import random
        rng = random.Random(chart["id"])
        bg = Image.new("RGBA", (SZ, SZ), dark)
        d = ImageDraw.Draw(bg)
        for _ in range(7):
            r = rng.randint(120, 300); x = rng.randint(-100, SZ); y = rng.randint(-100, SZ)
            mix = rng.uniform(.3, .8)
            col = tuple(int(dark[i] + (rgb[i] - dark[i]) * mix) for i in range(3))
            d.ellipse([x - r, y - r, x + r, y + r], fill=col)
        bg = bg.filter(ImageFilter.GaussianBlur(40))

    # Darken the bottom for legibility, then a colour wash on top
    shade = Image.new("RGBA", (SZ, SZ))
    sd = ImageDraw.Draw(shade)
    for y in range(SZ):
        t = y / SZ
        sd.line([(0, y), (SZ, y)], fill=(*dark, int(40 + 190 * t ** 1.8)))
    img = Image.alpha_composite(bg, shade)

    # Huge faint rank number in the background (own layer so the alpha actually blends)
    ghost = Image.new("RGBA", (SZ, SZ))
    ImageDraw.Draw(ghost).text((SZ - M + 30, -40), "1", font=_font(_BLACK, 380),
                               fill=(255, 255, 255, 38), anchor="ra")
    img = Image.alpha_composite(img, ghost)

    # Everything else goes on a transparent layer composited at the end
    layer = Image.new("RGBA", (SZ, SZ))
    draw = ImageDraw.Draw(layer)

    # Eyebrow: coloured pill with the period
    eb = _font(_BOLD, 22)
    label = _PERIOD_LABEL.get(period, "")
    kind = "ARTIST CHART" if chart["id"].startswith("artist:") else "CHART"
    pill = f"{kind}  ·  {label}"
    w = draw.textlength(pill, font=eb)
    draw.rounded_rectangle([M, M, M + w + 32, M + 42], radius=21, fill=rgb)
    draw.text((M + 16, M + 21), pill, font=eb, fill="white", anchor="lm")

    # Title: "TOP" small over the big chart name
    title = chart["title"]
    if chart["id"] == "top":
        head, main = "TOP", "50"
    elif chart["id"].startswith("genre:"):
        head, main = "TOP", title[4:] if title.lower().startswith("top ") else title
    else:
        head, main = "TOP SONGS", title
    main = main.upper()
    max_w = SZ - 2 * M
    mf = _fit_text(draw, main, _BLACK, max_w, 190 if chart["id"] == "top" else 130, 54)
    main = _ellipsize(draw, main, mf, max_w)
    hf = _font(_BLACK, 56)
    base_y = SZ - 150
    draw.text((M - 4, base_y), main, font=mf, fill="white", anchor="ls")
    asc = mf.getbbox(main, anchor="ls")[1]           # negative: height above baseline
    draw.text((M, base_y + asc - 14), head, font=hf, fill=light, anchor="ls")

    # Accent rule + "#1 song — artist" footer
    draw.rectangle([M, SZ - 112, M + 64, SZ - 106], fill=rgb)
    if chart["tracks"]:
        t = chart["tracks"][0]
        nf, sf = _font(_BOLD, 26), _font(_BOLD, 22)
        draw.text((M, SZ - 66), _ellipsize(draw, f"#1  {t.get('title') or ''}", nf, max_w),
                  font=nf, fill="white", anchor="ls")
        draw.text((M, SZ - 36), _ellipsize(draw, t.get("artist") or "", sf, max_w),
                  font=sf, fill=(255, 255, 255, 170), anchor="ls")

    img = Image.alpha_composite(img, layer)
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=90, optimize=True)
    return buf.getvalue()

@api.get("/api/charts/cover")
def api_chart_cover(chart: str, period: str = "week"):
    # A charts page asks for ~20 covers at once; share one chart computation between them
    hit = _charts_memo.get(period)
    if hit and _now() - hit[0] < 30:
        data = hit[1]
    else:
        data = api_charts(period)
        _charts_memo[period] = (_now(), data)
    found, artist = None, None
    for c in data["charts"]:
        if c["id"] == chart: found = c
    for a in data["artists"]:
        if a["chart"]["id"] == chart: found, artist = a["chart"], a["name"]
    if not found:
        raise HTTPException(404)
    top_id = found["tracks"][0]["id"] if found["tracks"] else 0
    key = (chart, period, top_id, state.get("accent"))
    jpg = _chart_cover_cache.get(key)
    if jpg is None:
        pic = None
        if artist:
            p, _ = _pic_paths(artist)
            pic = p.read_bytes() if p.exists() else None
        jpg = _make_chart_cover(found, period, pic)
        if len(_chart_cover_cache) > 200:
            _chart_cover_cache.clear()
        _chart_cover_cache[key] = jpg
    return Response(content=jpg, media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=600"})

# ── User accounts, sessions and personal mixes ────────────────────────────────
# Once the admin creates the first account, every /api route needs a session
# (cookie, so <audio>/<img> requests work) or an admin token.
SESSION_COOKIE = "lm_session"
SESSION_DAYS = 30
_auth_cache = {"users": None, "t": 0.0}

def init_users_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE COLLATE NOCASE NOT NULL,
            pw_hash TEXT NOT NULL,
            genres TEXT DEFAULT '[]',
            onboarded INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_mixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT, genres TEXT, track_ids TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit(); db.close()

init_users_db()

def _auth_required() -> bool:
    """True once any user account exists (the library password is checked separately)."""
    if _auth_cache["users"] is None or _now() - _auth_cache["t"] > 10:
        db = get_db()
        _auth_cache["users"] = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        db.close()
        _auth_cache["t"] = _now()
    return _auth_cache["users"] > 0

def _session_user(req: Request):
    """{'id','username','admin',...} for the cookie session, or None. id 0 = the admin."""
    tok = req.cookies.get(SESSION_COOKIE, "")
    if not tok:
        return None
    db = get_db()
    row = db.execute("SELECT user_id FROM sessions WHERE token=? AND expires>?", (tok, _now())).fetchone()
    user = None
    if row and row["user_id"] == 0:
        user = {"id": 0, "username": "admin", "admin": True, "onboarded": True, "genres": []}
    elif row:
        u = db.execute("SELECT id,username,genres,onboarded FROM users WHERE id=?", (row["user_id"],)).fetchone()
        if u:
            user = {"id": u["id"], "username": u["username"], "admin": False,
                    "onboarded": bool(u["onboarded"]), "genres": json.loads(u["genres"] or "[]")}
    db.close()
    return user


def _new_session(user_id: int, resp: Response, req: Optional[Request] = None):
    if req is not None and (req.url.scheme == "https" or req.headers.get("x-forwarded-proto") == "https"):
        resp.headers["x-lm-secure"] = "1"
    tok = secrets.token_urlsafe(32)
    db = get_db()
    db.execute("DELETE FROM sessions WHERE expires<?", (_now(),))
    db.execute("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)",
               (tok, user_id, _now() + SESSION_DAYS * 86400))
    db.commit(); db.close()
    secure = resp.headers.get("x-lm-secure") == "1"
    resp.set_cookie(SESSION_COOKIE, tok, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax", secure=secure)

@api.get("/api/auth/me")
def api_auth_me(req: Request):
    lib = bool(load_config().get("library_password_hash"))
    shared = req.cookies.get("lm_session", "") in _sessions
    return {"required": _lib_locked(), "library_password": lib, "shared": shared and not _session_user(req),
            "accounts": _auth_required(), "user": _session_user(req)}

@api.post("/api/auth/login")
async def api_auth_login(req: Request):
    """One login for everyone: user accounts, 'admin', or (blank username) the shared library password."""
    _rate_check(req)
    body = await req.json()
    username = (body.get("username") or "").strip()
    pw = str(body.get("password") or "")
    cfg = load_config()
    if not username:
        stored = cfg.get("library_password_hash", "")
        if stored and _check_pw(pw, stored):
            _rate_ok(req)
            return _login_response(req, {"user": None, "shared": True})
    elif username.lower() == "admin":
        stored = cfg.get("admin_password_hash", "")
        if stored and _check_pw(pw, stored):
            _rate_ok(req)
            token = secrets.token_hex(32)
            _admin_tokens.add(token)
            resp = JSONResponse({"user": {"id": 0, "username": "admin", "admin": True, "onboarded": True},
                                 "admin_token": token})
            _new_session(0, resp, req)
            return resp
    else:
        db = get_db()
        u = db.execute("SELECT id,username,pw_hash,onboarded FROM users WHERE username=?", (username,)).fetchone()
        db.close()
        if u and _check_pw(pw, u["pw_hash"]):
            _rate_ok(req)
            if not u["pw_hash"].startswith("scrypt$"):    # upgrade old hashes now that we know the password
                db = get_db()
                db.execute("UPDATE users SET pw_hash=? WHERE id=?", (_hash_pw(pw), u["id"]))
                db.commit(); db.close()
            resp = JSONResponse({"user": {"id": u["id"], "username": u["username"], "admin": False,
                                          "onboarded": bool(u["onboarded"])}})
            _new_session(u["id"], resp, req)
            return resp
    _rate_fail(req)
    await asyncio.sleep(0.4)
    raise HTTPException(401, "Wrong username or password" if username else "Wrong library password")

@api.post("/api/auth/logout")
def api_auth_logout(req: Request):
    tok = req.cookies.get(SESSION_COOKIE, "")
    _sessions.discard(tok)                                 # shared library-password session
    db = get_db(); db.execute("DELETE FROM sessions WHERE token=?", (tok,)); db.commit(); db.close()
    _admin_tokens.discard(req.headers.get("X-Admin-Token", ""))
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(SESSION_COOKIE)
    return resp

# ── Admin: manage accounts ──
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")

@api.get("/api/admin/users")
def api_users_list(req: Request):
    _require_admin(req)
    db = get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT id,username,onboarded,genres,created_at,COALESCE(is_admin,0) AS is_admin FROM users ORDER BY username").fetchall()]
    db.close()
    for r in rows:
        r["genres"] = json.loads(r["genres"] or "[]")
    return rows

@api.post("/api/admin/users")
async def api_users_create(req: Request):
    _require_admin(req)
    body = await req.json()
    username = (body.get("username") or "").strip()
    pw = body.get("password") or ""
    if not _USERNAME_RE.match(username) or username.lower() == "admin":
        raise HTTPException(400, "Username: 2–32 letters, numbers, dots, dashes or underscores (not 'admin')")
    _valid_new_pw(pw)
    if not load_config().get("admin_password_hash"):
        raise HTTPException(400, "Set an admin password first, or you'd be locked out once accounts are on")
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,pw_hash) VALUES(?,?)", (username, _hash_pw(pw)))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "That username is taken")
    finally:
        db.close()
    _auth_cache["users"] = None
    return {"status": "ok"}

@api.post("/api/admin/users/{uid}/password")
async def api_users_reset(uid: int, req: Request):
    _require_admin(req)
    pw = _valid_new_pw((await req.json()).get("password"))
    db = get_db()
    db.execute("UPDATE users SET pw_hash=? WHERE id=?", (_hash_pw(pw), uid))
    db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))     # sign them out everywhere
    db.commit(); db.close()
    return {"status": "ok"}

@api.delete("/api/admin/users/{uid}")
def api_users_delete(uid: int, req: Request):
    _require_admin(req)
    db = get_db()
    for t in ("sessions", "user_mixes", "likes"):
        db.execute(f"DELETE FROM {t} WHERE user_id=?", (uid,))
    db.execute("DELETE FROM friends WHERE user_id=? OR friend_id=?", (uid, uid))
    db.execute("DELETE FROM user_playlist_tracks WHERE playlist_id IN (SELECT id FROM user_playlists WHERE user_id=?)", (uid,))
    db.execute("DELETE FROM user_playlists WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit(); db.close()
    _auth_cache["users"] = None
    return {"status": "ok"}

# ── Genres + personal mix ──
def _genre_index() -> dict:
    """genre key -> {'labels', 'ids', 'covers'}; same normalisation as the charts."""
    db = get_db()
    rows = db.execute("SELECT id,genre,cover_id,COALESCE(album_artist,artist) AS a FROM tracks WHERE genre IS NOT NULL AND genre<>''").fetchall()
    db.close()
    idx: dict = {}
    for r in rows:
        key, label = _genre_parts(r["genre"])
        if not key:
            continue
        g = idx.setdefault(key, {"labels": {}, "ids": [], "covers": [], "artists": {}})
        if r["a"]:
            g["artists"][r["a"]] = g["artists"].get(r["a"], 0) + 1
        g["labels"][label] = g["labels"].get(label, 0) + 1
        g["ids"].append(r["id"])
        if r["cover_id"] and len(g["covers"]) < 4 and r["cover_id"] not in g["covers"]:
            g["covers"].append(r["cover_id"])
    return idx

@api.get("/api/genres")
def api_genres():
    out = [{"key": k, "label": max(g["labels"].items(), key=lambda kv: kv[1])[0],
            "count": len(g["ids"]), "covers": g["covers"],
            "artist": max(g["artists"].items(), key=lambda kv: kv[1])[0] if g["artists"] else ""}
           for k, g in _genre_index().items()]
    return sorted(out, key=lambda g: -g["count"])

def _require_user(req: Request) -> dict:
    u = _session_user(req)
    if not u or u["id"] == 0:
        raise HTTPException(401, "Log in with a user account")
    return u

def _build_mix(keys: list, size: int = 50) -> list:
    """Spread evenly across the picked genres, nudging towards songs people actually play."""
    import random as _r
    idx = _genre_index()
    db = get_db()
    plays = {r[0]: r[1] for r in db.execute("SELECT track_id, COUNT(*) FROM plays GROUP BY track_id").fetchall()}
    db.close()
    pools = []
    for k in keys:
        ids = list(dict.fromkeys(idx.get(k, {}).get("ids", [])))
        ids.sort(key=lambda i: -_r.random() * (1 + plays.get(i, 0)) ** .5)
        if ids:
            pools.append(ids)
    mix, seen = [], set()
    while pools and len(mix) < size:
        for p in list(pools):
            while p and p[0] in seen:
                p.pop(0)
            if not p:
                pools.remove(p)
                continue
            seen.add(p[0]); mix.append(p.pop(0))
            if len(mix) >= size:
                break
    _r.shuffle(mix)
    return mix

@api.post("/api/me/genres")
async def api_me_genres(req: Request):
    u = _require_user(req)
    valid = set(_genre_index())
    keys = [k for k in (await req.json()).get("genres", []) if k in valid][:20]
    if not keys:
        raise HTTPException(400, "Pick at least one genre")
    ids = _build_mix(keys)
    labels = {g["key"]: g["label"] for g in api_genres()}
    db = get_db()
    db.execute("UPDATE users SET genres=?, onboarded=1 WHERE id=?", (json.dumps(keys), u["id"]))
    db.execute("DELETE FROM user_mixes WHERE user_id=?", (u["id"],))
    cur = db.execute("INSERT INTO user_mixes(user_id,name,genres,track_ids) VALUES(?,?,?,?)",
                     (u["id"], f"{u['username']}'s Mix", json.dumps([labels[k] for k in keys]), json.dumps(ids)))
    db.commit(); mid = cur.lastrowid; db.close()
    return {"id": mid, "count": len(ids)}

@api.get("/api/me/mix")
def api_me_mix(req: Request):
    u = _require_user(req)
    db = get_db()
    m = db.execute("SELECT * FROM user_mixes WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
    if not m:
        db.close()
        return None
    ids = json.loads(m["track_ids"] or "[]")
    rows = {}
    if ids:
        for r in db.execute(f"SELECT id,title,artist,album,duration,cover_id,genre FROM tracks "
                            f"WHERE id IN ({','.join('?' * len(ids))})", ids):
            rows[r["id"]] = dict(r)
    db.close()
    return {"id": m["id"], "name": m["name"], "genres": json.loads(m["genres"] or "[]"),
            "created_at": m["created_at"], "tracks": [rows[i] for i in ids if i in rows]}

# ── Home: Made for You mixes + Top Picks ─────────────────────────────────────
_ENERGY = ("hip", "rap", "trap", "drill", "dance", "edm", "house", "electr", "techno", "rock", "metal",
           "punk", "pop", "reggaeton", "dubstep", "drum", "grime", "latin")
_CHILL = ("chill", "lofi", "lo-fi", "ambient", "acoustic", "jazz", "soul", "rnb", "r&b", "indie", "folk",
          "classical", "piano", "instrumental", "sleep", "relax")
_MIX_STYLES = {   # gradient blobs (c1, c2, c3, base)
    "new":     ["#ff2d55", "#ff8fa3", "#ff3b30", "#ffb3c1"],
    "heavy":   ["#ffd60a", "#ff6a00", "#ff9f0a", "#c2410c"],
    "ess":     ["#5b21ff", "#ff5fa2", "#8a2be2", "#3b0fa8"],
    "getup":   ["#ffcc00", "#ff2d2d", "#ff7a00", "#d61f1f"],
    "chill":   ["#00c2a8", "#0a84ff", "#30d158", "#0e7490"],
    "mine":    ["#ff375f", "#bf5af2", "#ff9f0a", "#7c3aed"],
    "friends": ["#30d158", "#0a84ff", "#64d2ff", "#1e3a8a"],
}

def _ensure_play_user_col():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS plays (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  track_id INTEGER NOT NULL, listener TEXT, played_at REAL NOT NULL)""")
    cols = [r[1] for r in db.execute("PRAGMA table_info(plays)").fetchall()]
    if "user_id" not in cols:
        db.execute("ALTER TABLE plays ADD COLUMN user_id INTEGER")
        db.commit()
    db.close()

_ensure_play_user_col()

def _tracks_by_ids(db, ids: list) -> list:
    if not ids:
        return []
    rows = {r["id"]: dict(r) for r in db.execute(
        f"SELECT id,title,artist,album,duration,cover_id,genre,COALESCE(album_artist,artist) AS main_artist "
        f"FROM tracks WHERE id IN ({','.join('?' * len(ids))})", ids)}
    return [rows[i] for i in ids if i in rows]

def _artist_line(tracks: list, n: int = 5) -> list:
    seen = []
    for t in tracks:
        a = (t.get("artist") or "").strip()
        if a and a not in seen:
            seen.append(a)
        if len(seen) >= n:
            break
    return seen

@api.get("/api/me/home")
def api_me_home(req: Request):
    import random as _r
    u = _session_user(req)
    if not u or u["id"] == 0:
        return {"mixes": [], "picks": []}
    rng = _r.Random(f"{u['id']}:{_dt.date.today().isoformat()}")    # mixes refresh daily
    keys = set(u.get("genres") or [])
    db = get_db()
    allrows = [dict(r) for r in db.execute(
        "SELECT id,genre,added_at,mtime,COALESCE(album_artist,artist) AS a FROM tracks").fetchall()]
    gkey = {r["id"]: (_genre_parts(r["genre"])[0] or "") for r in allrows}
    pool = [r for r in allrows if not keys or gkey[r["id"]] in keys]
    gplays = {r[0]: r[1] for r in db.execute("SELECT track_id, COUNT(*) FROM plays GROUP BY track_id")}
    mine = [(r[0], r[1]) for r in db.execute(
        "SELECT track_id, COUNT(*) n FROM plays WHERE user_id=? GROUP BY track_id ORDER BY n DESC", (u["id"],))]
    my_total = sum(n for _, n in mine)

    def mk(key, title, ids, sub=""):
        tr = _tracks_by_ids(db, list(dict.fromkeys(ids))[:40])
        if len(tr) < 5:
            return None
        return {"id": key, "title": title, "sub": sub, "colors": _MIX_STYLES[key],
                "artists": _artist_line(tr), "tracks": tr}

    mixes = []
    newest = sorted(pool, key=lambda r: (r["added_at"] or "", r["mtime"] or 0), reverse=True)
    mixes.append(mk("new", "New Music", [r["id"] for r in newest[:30]], "The newest songs in the genres you like"))
    mixes.append(mk("heavy", "Heavy Rotation", [i for i, _ in mine[:30]], "What you've been playing the most"))
    # Essentials: favourite artists (yours, else the server's) → their most-played songs
    art_score: dict = {}
    for i, n in (mine or [(r["id"], gplays.get(r["id"], 0)) for r in pool]):
        a = next((r["a"] for r in allrows if r["id"] == i), None)
        if a:
            art_score[a] = art_score.get(a, 0) + n + 0.01
    top_artists = sorted(art_score, key=lambda a: -art_score[a])[:6]
    ess = []
    for a in top_artists:
        ids = [r["id"] for r in pool if r["a"] == a] or [r["id"] for r in allrows if r["a"] == a]
        ids.sort(key=lambda i: -(gplays.get(i, 0) + rng.random()))
        ess += ids[:5]
    mixes.append(mk("ess", "Your Essentials", ess, "Must-hear songs from your favourite artists"))
    energy = [r["id"] for r in pool if any(k in gkey[r["id"]] for k in _ENERGY)]
    rng.shuffle(energy)
    mixes.append(mk("getup", "Get Up!", energy, "Upbeat songs to get you moving"))
    chill = [r["id"] for r in allrows if any(k in gkey[r["id"]] for k in _CHILL)]
    rng.shuffle(chill)
    mixes.append(mk("chill", "Chill", chill, "Laid-back songs to slow down to"))
    saved = db.execute("SELECT name,track_ids FROM user_mixes WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
    if saved:
        mixes.append(mk("mine", saved["name"], json.loads(saved["track_ids"] or "[]"), "Your genre mix"))
    mixes.append(_friends_mix(db, u["id"], mk))
    mixes = [m for m in mixes if m]

    # Top Picks — only once there's enough listening history to be meaningful
    picks = []
    if my_total >= 10 and mixes:
        station = []
        for m in mixes:
            station += [t["id"] for t in m["tracks"]]
        station = list(dict.fromkeys(station)); rng.shuffle(station)
        picks.append({"type": "station", "eyebrow": "Made for you", "title": f"Station for {u['username']}",
                      "tracks": _tracks_by_ids(db, station[:60])})
        fav = top_artists[0] if top_artists else None
        if fav:
            played = {i for i, _ in mine}
            alb = db.execute("""SELECT album, COALESCE(album_artist,artist) AS artist, MAX(year) AS year,
                       COUNT(*) AS track_count, SUM(duration) AS total_duration, MIN(cover_id) AS cover_id,
                       SUM(CASE WHEN id IN (%s) THEN 1 ELSE 0 END) AS heard
                FROM tracks WHERE COALESCE(album_artist,artist)=? AND album IS NOT NULL AND album<>''
                GROUP BY album ORDER BY heard ASC, MAX(added_at) DESC LIMIT 1""" % (",".join("?" * len(played)) or "NULL"),
                list(played) + [fav]).fetchone()
            if alb:
                picks.append({"type": "album", "eyebrow": f"More from {fav}", "album": dict(alb)})
        nm = next((m for m in mixes if m["id"] == "new"), None)
        if nm:
            picks.append({"type": "mix", "eyebrow": "Made for you", "mix": nm})
        gu = next((m for m in mixes if m["id"] == "getup"), None)
        if gu:
            picks.append({"type": "vibe", "eyebrow": "Vibes for you", "title": "Energy",
                          "sub": "Turn it up with these high-energy tracks", "tracks": gu["tracks"]})
        if keys:
            ph = ",".join("?" * len(pool[:900]))
            rel = db.execute(f"""SELECT album, COALESCE(album_artist,artist) AS artist, MAX(year) AS year,
                       COUNT(*) AS track_count, SUM(duration) AS total_duration, MIN(cover_id) AS cover_id
                FROM tracks WHERE id IN ({ph}) AND album IS NOT NULL AND album<>''
                GROUP BY album ORDER BY MAX(year) DESC, MAX(added_at) DESC LIMIT 1""",
                [r["id"] for r in pool[:900]]).fetchone() if pool else None
            if rel:
                picks.append({"type": "album", "eyebrow": "New release", "album": dict(rel)})
    db.close()
    return {"mixes": mixes, "picks": picks, "brand": state["name"]}

# ── Search + genre pages ──────────────────────────────────────────────────────
@api.get("/api/search")
def api_search(q: str = ""):
    q = q.strip()
    if not q:
        return {"tracks": [], "artists": [], "albums": []}
    like = f"%{q}%"
    db = get_db()
    tracks = [dict(r) for r in db.execute(
        """SELECT id,title,artist,album,duration,cover_id FROM tracks
           WHERE title LIKE ? OR artist LIKE ? OR album LIKE ?
           ORDER BY (title LIKE ?) DESC, title LIMIT 30""", (like, like, like, f"{q}%")).fetchall()]
    artists = [dict(r) for r in db.execute(
        """SELECT COALESCE(album_artist,artist) AS name, COUNT(DISTINCT album) AS album_count,
                  COUNT(*) AS track_count, MIN(cover_id) AS cover_id
           FROM tracks WHERE COALESCE(album_artist,artist) LIKE ? GROUP BY name
           ORDER BY (name LIKE ?) DESC, track_count DESC LIMIT 12""", (like, f"{q}%")).fetchall()]
    albums = [dict(r) for r in db.execute(
        """SELECT album, COALESCE(album_artist,artist) AS artist, MAX(year) AS year, COUNT(*) AS track_count,
                  SUM(duration) AS total_duration, MIN(cover_id) AS cover_id
           FROM tracks WHERE album IS NOT NULL AND album<>'' AND (album LIKE ? OR COALESCE(album_artist,artist) LIKE ?)
           GROUP BY album ORDER BY (album LIKE ?) DESC, album LIMIT 12""", (like, like, f"{q}%")).fetchall()]
    db.close()
    return {"tracks": tracks, "artists": artists, "albums": albums}

@api.get("/api/genres/{key}")
def api_genre_page(key: str):
    g = _genre_index().get(key)
    if not g:
        raise HTTPException(404, "Unknown genre")
    label = max(g["labels"].items(), key=lambda kv: kv[1])[0]
    return _collection_page(key, label, list(dict.fromkeys(g["ids"])))

def _decade_label(d: int) -> str:
    return f"{d % 100:02d}s" if d < 2000 else f"{d}s"

@api.get("/api/decades")
def api_decades():
    db = get_db()
    rows = db.execute("""SELECT (year/10)*10 AS d, COUNT(*) AS n FROM tracks
                         WHERE year BETWEEN 1900 AND 2100 GROUP BY d ORDER BY d DESC""").fetchall()
    out = []
    for r in rows:
        a = db.execute("""SELECT COALESCE(album_artist,artist) AS a, COUNT(*) c FROM tracks WHERE (year/10)*10=?
                          AND COALESCE(album_artist,artist) IS NOT NULL GROUP BY a ORDER BY c DESC LIMIT 1""", (r["d"],)).fetchone()
        out.append({"decade": r["d"], "label": _decade_label(r["d"]), "count": r["n"], "artist": a["a"] if a else ""})
    db.close()
    return out

@api.get("/api/decades/{decade}")
def api_decade_page(decade: int):
    db = get_db()
    ids = [r[0] for r in db.execute("SELECT id FROM tracks WHERE year BETWEEN ? AND ?", (decade, decade + 9))]
    db.close()
    if not ids:
        raise HTTPException(404, "No songs from that decade")
    return _collection_page(f"decade-{decade}", _decade_label(decade), ids)

def _collection_page(key: str, label: str, ids: list):
    """Feature cards, playlists, top songs, albums and artists for any set of songs (a genre, a decade…)."""
    import random as _r
    db = get_db()
    tr = _tracks_by_ids(db, ids)
    plays = {r[0]: r[1] for r in db.execute("SELECT track_id, COUNT(*) FROM plays GROUP BY track_id")}
    added = {r[0]: (r[1] or "", r[2] or 0) for r in db.execute(
        f"SELECT id,added_at,mtime FROM tracks WHERE id IN ({','.join('?' * len(ids))})", ids)}
    db.close()
    rng = _r.Random(f"{key}:{_dt.date.today().isoformat()}")
    by_play = sorted(tr, key=lambda t: (-plays.get(t["id"], 0), rng.random()))
    newest = sorted(tr, key=lambda t: added.get(t["id"], ("", 0)), reverse=True)
    albums: dict = {}
    artists: dict = {}
    for t in tr:
        if t["album"]:
            a = albums.setdefault(t["album"], {"album": t["album"], "artist": t["main_artist"], "track_count": 0,
                                               "total_duration": 0, "cover_id": t["cover_id"], "plays": 0, "year": None})
            a["track_count"] += 1; a["total_duration"] += t["duration"] or 0; a["plays"] += plays.get(t["id"], 0)
            a["cover_id"] = a["cover_id"] or t["cover_id"]
        ar = artists.setdefault(t["main_artist"] or "Unknown", {"name": t["main_artist"] or "Unknown", "track_count": 0,
                                                                "album_count": 0, "cover_id": t["cover_id"], "plays": 0})
        ar["track_count"] += 1; ar["plays"] += plays.get(t["id"], 0)
    for ar in artists.values():
        ar["album_count"] = len({t["album"] for t in tr if t["main_artist"] == ar["name"] and t["album"]})
    alb_list = sorted(albums.values(), key=lambda a: -a["plays"])
    art_list = sorted(artists.values(), key=lambda a: (-a["plays"], -a["track_count"]))
    shuffled = tr[:]; rng.shuffle(shuffled)

    def pl(pid, title, sub, tracks, colors):
        tracks = tracks[:40]
        return {"id": pid, "title": title, "sub": sub, "colors": colors,
                "artists": _artist_line(tracks), "tracks": tracks} if len(tracks) >= 3 else None
    hue = int(hashlib.md5(key.encode()).hexdigest()[:2], 16)
    pal = lambda s: [f"hsl({(hue + s) % 360},90%,58%)", f"hsl({(hue + s + 40) % 360},85%,65%)",
                     f"hsl({(hue + s - 30) % 360},90%,50%)", f"hsl({(hue + s + 10) % 360},70%,38%)"]
    playlists = [p for p in [
        pl("hits", f"{label} Hits", "The most played on the server", by_play, pal(0)),
        pl("new", f"New in {label}", "Freshly added", newest, pal(70)),
        pl("ess", f"{label} Essentials", "One great song per artist",
           list({t["main_artist"]: t for t in reversed(by_play)}.values())[::-1], pal(150)),
        pl("deep", f"{label} Deep Cuts", "The ones you might have missed", by_play[::-1], pal(220)),
        pl("mix", f"{label} Mix", "A fresh shuffle every day", shuffled, pal(290)),
    ] if p]
    hero = []
    if newest and newest[0]["album"] in albums:
        hero.append({"type": "album", "eyebrow": "Newest album", "album": albums[newest[0]["album"]]})
    if art_list:
        hero.append({"type": "artist", "eyebrow": "Top artist", "artist": art_list[0]})
    if playlists:
        hero.append({"type": "mix", "eyebrow": "Updated playlist", "mix": playlists[0]})
    return {"key": key, "label": label, "count": len(tr), "hero": hero, "playlists": playlists,
            "top": by_play[:16], "albums": alb_list[:18], "artists": art_list[:18], "brand": state["name"]}

# ── Rewind: per-user listening stats ─────────────────────────────────────────
# A "play" is logged after ~30s of listening; minutes assume the song was heard in full.
def _user_plays(db, uid: int, start: float, end: float) -> list:
    return [dict(r) for r in db.execute(
        """SELECT p.track_id, p.played_at, t.title, t.artist, t.album, t.duration, t.cover_id, t.genre,
                  COALESCE(t.album_artist,t.artist) AS main_artist
           FROM plays p JOIN tracks t ON t.id=p.track_id
           WHERE p.user_id=? AND p.played_at>=? AND p.played_at<?""", (uid, start, end)).fetchall()]

def _rewind_stats(rows: list, top_n: int = 50) -> dict:
    songs: dict = {}; artists: dict = {}; albums: dict = {}; genres: dict = {}
    minutes = 0.0
    for r in rows:
        m = (r["duration"] or 180) / 60
        minutes += m
        s = songs.setdefault(r["track_id"], {"id": r["track_id"], "title": r["title"], "artist": r["artist"],
                                             "album": r["album"], "duration": r["duration"], "cover_id": r["cover_id"], "plays": 0})
        s["plays"] += 1
        a = artists.setdefault(r["main_artist"] or "Unknown", {"name": r["main_artist"] or "Unknown", "minutes": 0,
                                                                "plays": 0, "cover_id": r["cover_id"]})
        a["minutes"] += m; a["plays"] += 1
        if r["album"]:
            al = albums.setdefault(r["album"], {"album": r["album"], "artist": r["main_artist"], "cover_id": r["cover_id"],
                                                "plays": 0, "track_count": 0, "total_duration": 0})
            al["plays"] += 1
        gk, gl = _genre_parts(r["genre"])
        if gk:
            genres[gl] = genres.get(gl, 0) + m
    for a in artists.values():
        a["minutes"] = round(a["minutes"])
    return {"minutes": round(minutes), "plays": len(rows), "songs_count": len(songs), "artists_count": len(artists),
            "top_songs": sorted(songs.values(), key=lambda s: -s["plays"])[:top_n],
            "top_artists": sorted(artists.values(), key=lambda a: (-a["minutes"], -a["plays"]))[:10],
            "top_albums": sorted(albums.values(), key=lambda a: -a["plays"])[:12],
            "top_genre": max(genres.items(), key=lambda kv: kv[1])[0] if genres else None,
            "days": len({_dt.date.fromtimestamp(r["played_at"]) for r in rows})}

@api.get("/api/me/rewind")
def api_me_rewind(req: Request, year: Optional[int] = None, month: Optional[int] = None):
    u = _require_user(req)
    today = _dt.date.today()
    year = year or today.year
    db = get_db()
    yrs = [int(r[0]) for r in db.execute(
        "SELECT DISTINCT strftime('%Y', played_at, 'unixepoch', 'localtime') FROM plays WHERE user_id=? ORDER BY 1 DESC",
        (u["id"],)) if r[0]]
    ystart = _dt.datetime(year, 1, 1).timestamp(); yend = _dt.datetime(year + 1, 1, 1).timestamp()
    year_rows = _user_plays(db, u["id"], ystart, yend)
    db.close()
    months = sorted({_dt.datetime.fromtimestamp(r["played_at"]).month for r in year_rows})
    if month is None:
        month = months[-1] if months else (today.month if year == today.year else 12)
    mrows = [r for r in year_rows if _dt.datetime.fromtimestamp(r["played_at"]).month == month]
    return {"year": year, "years": yrs or [today.year], "months": months, "month": month,
            "month_stats": _rewind_stats(mrows, 16), "year_stats": _rewind_stats(year_rows, 50),
            "end_of_year": today.month == 12 and year == today.year}

@api.get("/api/me/rewind/week")
def api_me_rewind_week(req: Request):
    u = _require_user(req)
    today = _dt.date.today()
    monday = today - _dt.timedelta(days=today.weekday())
    w0 = _dt.datetime.combine(monday, _dt.time()).timestamp()
    db = get_db()
    rows = _user_plays(db, u["id"], w0, w0 + 7 * 86400)
    prev = _user_plays(db, u["id"], w0 - 7 * 86400, w0)
    seen_before = {r[0] for r in db.execute(
        """SELECT DISTINCT COALESCE(t.album_artist,t.artist) FROM plays p JOIN tracks t ON t.id=p.track_id
           WHERE p.user_id=? AND p.played_at<?""", (u["id"], w0))}
    db.close()
    st = _rewind_stats(rows, 10)
    pv = _rewind_stats(prev, 1)
    daily = [0.0] * 7
    for r in rows:
        daily[_dt.datetime.fromtimestamp(r["played_at"]).weekday()] += (r["duration"] or 180) / 60
    new_artists = [a for a in st["top_artists"] if a["name"] not in seen_before]
    return {"start": monday.isoformat(), "end": (monday + _dt.timedelta(days=6)).isoformat(), **st,
            "prev_minutes": pv["minutes"], "daily": [round(x) for x in daily], "today": today.weekday(),
            "new_artists": new_artists[:5]}

@api.get("/api/me/rewind/playlists")
def api_me_rewind_playlists(req: Request):
    """One Rewind playlist per year the user has listened in: their 50 most-played songs."""
    u = _session_user(req)
    if not u or u["id"] == 0:
        return []
    db = get_db()
    out = []
    for (y,) in db.execute("""SELECT DISTINCT strftime('%Y', played_at, 'unixepoch', 'localtime') FROM plays
                              WHERE user_id=? ORDER BY 1 DESC""", (u["id"],)).fetchall():
        y = int(y)
        rows = _user_plays(db, u["id"], _dt.datetime(y, 1, 1).timestamp(), _dt.datetime(y + 1, 1, 1).timestamp())
        st = _rewind_stats(rows, 50)
        tracks = [dict(t, main_artist=t["artist"]) for t in st["top_songs"]]
        if len(tracks) >= 5:
            out.append({"id": f"rewind-{y}", "year": y, "title": f"Rewind {y}", "short": f"'{y % 100:02d}",
                        "sub": f"Your most-played songs of {y}", "colors": ["#ffb300", "#ff3d00", "#ff7a00", "#ff2d2d"],
                        "artists": _artist_line(tracks), "tracks": tracks, "minutes": st["minutes"]})
    db.close()
    return out

# ── Likes, user playlists and lyrics ──────────────────────────────────────────
def init_library_feats_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS likes (
            user_id INTEGER NOT NULL, track_id INTEGER NOT NULL, created REAL NOT NULL,
            PRIMARY KEY (user_id, track_id)
        );
        CREATE TABLE IF NOT EXISTS user_playlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
            description TEXT DEFAULT '', shared INTEGER DEFAULT 0, created REAL, updated REAL
        );
        CREATE TABLE IF NOT EXISTS user_playlist_tracks (
            playlist_id INTEGER NOT NULL, track_id INTEGER NOT NULL, pos REAL NOT NULL, added REAL
        );
        CREATE INDEX IF NOT EXISTS idx_upt ON user_playlist_tracks(playlist_id, pos);
        CREATE TABLE IF NOT EXISTS lyrics (
            track_id INTEGER PRIMARY KEY, synced TEXT, plain TEXT, source TEXT,
            instrumental INTEGER DEFAULT 0, found INTEGER DEFAULT 0, fetched REAL
        );
    """)
    db.commit(); db.close()

init_library_feats_db()
state.setdefault("lyrics_online", load_config().get("lyrics_online", True))

def _me_id(req: Request) -> int:
    """Whose likes/playlists: the account (admin = 0); on an open, account-less server everyone is the owner (0)."""
    u = _session_user(req)
    if u:
        return u["id"]
    if _is_admin(req) or not _lib_locked():
        return 0
    raise HTTPException(401, "Log in with your own account to use likes and playlists")

_TRACK_SEL = "t.id,t.title,t.artist,t.album,t.duration,t.cover_id,t.year,t.genre"

# ── Likes ──
@api.get("/api/me/likes")
def api_likes(req: Request, ids_only: bool = False):
    uid = _me_id(req)
    db = get_db()
    if ids_only:
        ids = [r[0] for r in db.execute("SELECT track_id FROM likes WHERE user_id=?", (uid,))]
        db.close()
        return {"ids": ids}
    rows = [dict(r) for r in db.execute(
        f"SELECT {_TRACK_SEL}, l.created AS liked_at FROM likes l JOIN tracks t ON t.id=l.track_id "
        "WHERE l.user_id=? ORDER BY l.created DESC", (uid,))]
    db.close()
    return {"tracks": rows}

@api.post("/api/me/likes/{track_id}")
def api_like(track_id: int, req: Request):
    uid = _me_id(req)
    db = get_db()
    if not db.execute("SELECT 1 FROM tracks WHERE id=?", (track_id,)).fetchone():
        db.close(); raise HTTPException(404)
    db.execute("INSERT OR IGNORE INTO likes(user_id,track_id,created) VALUES(?,?,?)", (uid, track_id, _now()))
    db.commit(); db.close()
    return {"liked": True}

@api.delete("/api/me/likes/{track_id}")
def api_unlike(track_id: int, req: Request):
    uid = _me_id(req)
    db = get_db(); db.execute("DELETE FROM likes WHERE user_id=? AND track_id=?", (uid, track_id)); db.commit(); db.close()
    return {"liked": False}

# ── User playlists ──
def _owner_name(db, uid: int) -> str:
    if uid == 0:
        return "admin" if _auth_required() else state["name"]
    r = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    return r[0] if r else "someone"

def _pl_summary(db, row, me: int) -> dict:
    d = dict(row)
    d["count"] = db.execute("SELECT COUNT(*) FROM user_playlist_tracks WHERE playlist_id=?", (d["id"],)).fetchone()[0]
    d["covers"] = [r[0] for r in db.execute(
        """SELECT t.cover_id FROM user_playlist_tracks p JOIN tracks t ON t.id=p.track_id
           WHERE p.playlist_id=? AND t.cover_id IS NOT NULL GROUP BY t.cover_id ORDER BY MIN(p.pos) LIMIT 4""", (d["id"],))]
    d["owner"] = _owner_name(db, d["user_id"])
    d["mine"] = d["user_id"] == me
    d["shared"] = bool(d["shared"])
    return d

def _get_pl(db, pid: int, me: int, write=False):
    r = db.execute("SELECT * FROM user_playlists WHERE id=?", (pid,)).fetchone()
    if not r or (r["user_id"] != me and (write or not r["shared"])):
        db.close(); raise HTTPException(404, "Playlist not found")
    return r

@api.get("/api/me/playlists")
def api_my_playlists(req: Request):
    me = _me_id(req)
    db = get_db()
    mine = [_pl_summary(db, r, me) for r in db.execute(
        "SELECT * FROM user_playlists WHERE user_id=? ORDER BY updated DESC", (me,))]
    shared = [_pl_summary(db, r, me) for r in db.execute(
        "SELECT * FROM user_playlists WHERE shared=1 AND user_id<>? ORDER BY updated DESC", (me,))]
    db.close()
    return {"mine": mine, "shared": shared}

def _clean_pl_name(v) -> str:
    v = re.sub(r"\s+", " ", str(v or "")).strip()[:60]
    if not v:
        raise HTTPException(400, "Give the playlist a name")
    return v

@api.post("/api/me/playlists")
async def api_pl_create(req: Request):
    me = _me_id(req)
    body = await req.json()
    name = _clean_pl_name(body.get("name"))
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM user_playlists WHERE user_id=?", (me,)).fetchone()[0] >= 500:
        db.close(); raise HTTPException(400, "That's a lot of playlists. Delete some first")
    cur = db.execute("INSERT INTO user_playlists(user_id,name,description,shared,created,updated) VALUES(?,?,?,?,?,?)",
                     (me, name, str(body.get("description") or "")[:300], 1 if body.get("shared") else 0, _now(), _now()))
    pid = cur.lastrowid
    ids = [int(i) for i in (body.get("track_ids") or []) if str(i).isdigit()][:5000]
    for n, tid in enumerate(ids):
        db.execute("INSERT INTO user_playlist_tracks(playlist_id,track_id,pos,added) VALUES(?,?,?,?)", (pid, tid, n, _now()))
    db.commit(); db.close()
    return {"id": pid}

@api.get("/api/me/playlists/{pid}")
def api_pl_get(pid: int, req: Request):
    me = _me_id(req)
    db = get_db()
    r = _get_pl(db, pid, me)
    d = _pl_summary(db, r, me)
    d["tracks"] = [dict(x) for x in db.execute(
        f"SELECT {_TRACK_SEL}, p.rowid AS entry FROM user_playlist_tracks p JOIN tracks t ON t.id=p.track_id "
        "WHERE p.playlist_id=? ORDER BY p.pos", (pid,))]
    db.close()
    return d

@api.patch("/api/me/playlists/{pid}")
async def api_pl_edit(pid: int, req: Request):
    me = _me_id(req)
    body = await req.json()
    db = get_db()
    _get_pl(db, pid, me, write=True)
    if "name" in body:
        db.execute("UPDATE user_playlists SET name=? WHERE id=?", (_clean_pl_name(body["name"]), pid))
    if "description" in body:
        db.execute("UPDATE user_playlists SET description=? WHERE id=?", (str(body["description"] or "")[:300], pid))
    if "shared" in body:
        db.execute("UPDATE user_playlists SET shared=? WHERE id=?", (1 if body["shared"] else 0, pid))
    if isinstance(body.get("order"), list):          # list of entry ids in their new order
        for n, entry in enumerate(body["order"][:5000]):
            db.execute("UPDATE user_playlist_tracks SET pos=? WHERE rowid=? AND playlist_id=?", (n, int(entry), pid))
    db.execute("UPDATE user_playlists SET updated=? WHERE id=?", (_now(), pid))
    db.commit(); db.close()
    return {"status": "ok"}

@api.delete("/api/me/playlists/{pid}")
def api_pl_delete(pid: int, req: Request):
    me = _me_id(req)
    db = get_db()
    _get_pl(db, pid, me, write=True)
    db.execute("DELETE FROM user_playlist_tracks WHERE playlist_id=?", (pid,))
    db.execute("DELETE FROM user_playlists WHERE id=?", (pid,))
    db.commit(); db.close()
    return {"status": "ok"}

@api.post("/api/me/playlists/{pid}/tracks")
async def api_pl_add(pid: int, req: Request):
    me = _me_id(req)
    body = await req.json()
    ids = [int(i) for i in (body.get("track_ids") or []) if str(i).isdigit()][:5000]
    db = get_db()
    _get_pl(db, pid, me, write=True)
    have = {r[0] for r in db.execute("SELECT track_id FROM user_playlist_tracks WHERE playlist_id=?", (pid,))}
    top = db.execute("SELECT COALESCE(MAX(pos),-1) FROM user_playlist_tracks WHERE playlist_id=?", (pid,)).fetchone()[0]
    added = 0
    for tid in ids:
        if tid in have and not body.get("allow_duplicates"):
            continue
        top += 1; added += 1; have.add(tid)
        db.execute("INSERT INTO user_playlist_tracks(playlist_id,track_id,pos,added) VALUES(?,?,?,?)", (pid, tid, top, _now()))
    db.execute("UPDATE user_playlists SET updated=? WHERE id=?", (_now(), pid))
    db.commit(); db.close()
    return {"added": added, "skipped": len(ids) - added}

@api.delete("/api/me/playlists/{pid}/tracks/{entry}")
def api_pl_remove(pid: int, entry: int, req: Request):
    me = _me_id(req)
    db = get_db()
    _get_pl(db, pid, me, write=True)
    db.execute("DELETE FROM user_playlist_tracks WHERE rowid=? AND playlist_id=?", (entry, pid))
    db.execute("UPDATE user_playlists SET updated=? WHERE id=?", (_now(), pid))
    db.commit(); db.close()
    return {"status": "ok"}

# ── Lyrics: .lrc file → embedded tags → LRCLIB (lrclib.net, free & open) ──
_LRC_LINE = re.compile(r"\[(\d{1,3}):(\d{1,2})(?:[.:](\d{1,3}))?\]")
LRCLIB_UA = "leon.music (https://github.com/weareleon/leonmusic)"

def _parse_lrc(text: str) -> list:
    out = []
    for raw in (text or "").splitlines():
        stamps = list(_LRC_LINE.finditer(raw))
        if not stamps:
            continue
        words = _LRC_LINE.sub("", raw).strip()
        for m in stamps:
            frac = m.group(3) or "0"
            t = int(m.group(1)) * 60 + int(m.group(2)) + int(frac) / (10 ** len(frac))
            out.append({"t": round(t, 2), "text": words})
    return sorted(out, key=lambda x: x["t"])

def _embedded_lyrics(path: Path) -> str:
    try:
        f = MutagenFile(str(path))
        if f is None or not f.tags:
            return ""
        tags = f.tags
        for k in list(tags.keys()):
            if str(k).startswith("USLT"):
                return str(tags[k].text)
        for k in ("LYRICS", "lyrics", "UNSYNCEDLYRICS", "\xa9lyr"):
            if k in tags:
                v = tags[k]
                return str(v[0] if isinstance(v, list) else v)
    except Exception:
        pass
    return ""

def _lrclib_lookup(artist: str, title: str, album: str, duration) -> Optional[dict]:
    def get(url):
        req = urllib.request.Request(url, headers={"User-Agent": LRCLIB_UA})
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
    q = {"artist_name": artist, "track_name": title}
    if album:
        q["album_name"] = album
    if duration:
        q["duration"] = int(round(duration))
    hit = get("https://lrclib.net/api/get?" + _urlencode(q))
    if hit:
        return hit
    res = get("https://lrclib.net/api/search?" + _urlencode({"artist_name": artist, "track_name": title})) or []
    if duration:
        res = [r for r in res if r.get("duration") and abs(r["duration"] - duration) <= 4] or res[:0]
    return next((r for r in res if r.get("syncedLyrics")), None) or (res[0] if res else None)

@api.get("/api/lyrics/{track_id}")
def api_lyrics(track_id: int):
    db = get_db()
    t = db.execute("SELECT path,title,artist,album,duration FROM tracks WHERE id=?", (track_id,)).fetchone()
    db.close()
    if not t:
        raise HTTPException(404)
    def answer(synced_txt, plain, source, instrumental=False):
        synced = _parse_lrc(synced_txt) if synced_txt else []
        if not synced and plain and _LRC_LINE.search(plain):       # plain text that is really LRC
            synced, plain = _parse_lrc(plain), _LRC_LINE.sub("", plain)
        return {"found": bool(synced or plain or instrumental), "synced": synced,
                "plain": (plain or "").strip(), "source": source, "instrumental": bool(instrumental)}
    # 1) a .lrc file next to the song
    path = Path(t["path"])
    lrc = path.with_suffix(".lrc")
    if lrc.exists():
        try:
            return answer(lrc.read_text(encoding="utf-8", errors="replace"), "", "file")
        except Exception:
            pass
    # 2) lyrics saved in the file's tags
    emb = _embedded_lyrics(path)
    if emb.strip():
        return answer("", emb, "tags")
    # 3) cached LRCLIB result (misses are retried after a week)
    db = get_db()
    c = db.execute("SELECT * FROM lyrics WHERE track_id=?", (track_id,)).fetchone()
    if c and (c["found"] or _now() - (c["fetched"] or 0) < 7 * 86400):
        db.close()
        return answer(c["synced"], c["plain"], c["source"], c["instrumental"]) if c["found"] else \
            {"found": False, "synced": [], "plain": "", "source": None, "instrumental": False}
    db.close()
    if not state.get("lyrics_online", True):
        return {"found": False, "synced": [], "plain": "", "source": None, "instrumental": False, "disabled": True}
    if not (t["artist"] and t["title"]):
        return {"found": False, "synced": [], "plain": "", "source": None, "instrumental": False}
    try:
        hit = _lrclib_lookup(t["artist"], t["title"], t["album"] or "", t["duration"])
    except Exception:
        return {"found": False, "synced": [], "plain": "", "source": None, "instrumental": False, "error": "unreachable"}
    db = get_db()
    db.execute("INSERT OR REPLACE INTO lyrics(track_id,synced,plain,source,instrumental,found,fetched) VALUES(?,?,?,?,?,?,?)",
               (track_id, (hit or {}).get("syncedLyrics") or "", (hit or {}).get("plainLyrics") or "", "lrclib",
                1 if (hit or {}).get("instrumental") else 0, 1 if hit else 0, _now()))
    db.commit(); db.close()
    if not hit:
        return {"found": False, "synced": [], "plain": "", "source": None, "instrumental": False}
    return answer(hit.get("syncedLyrics") or "", hit.get("plainLyrics") or "", "lrclib", hit.get("instrumental"))

# ── Album page extras: Featured On, More from…, You may also like ────────────
_ALBUM_COLS = """album, COALESCE(album_artist,artist) AS artist, MAX(year) AS year, COUNT(*) AS track_count,
                 SUM(duration) AS total_duration, MIN(cover_id) AS cover_id"""

@api.get("/api/albums/related")
def api_album_related(album: str):
    db = get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT id,genre,year,playlist,COALESCE(album_artist,artist) AS a FROM tracks WHERE album=?", (album,))]
    if not rows:
        db.close(); raise HTTPException(404, "Unknown album")
    artists = sorted({r["a"] for r in rows if r["a"]})
    # Featured on: folder playlists holding songs from this album
    featured = []
    for name in sorted({r["playlist"] for r in rows if r["playlist"]}):
        n_in = sum(1 for r in rows if r["playlist"] == name)
        tot = db.execute("SELECT COUNT(*) FROM tracks WHERE playlist=?", (name,)).fetchone()[0]
        covers = [c[0] for c in db.execute(
            """SELECT cover_id FROM tracks WHERE playlist=? AND cover_id IS NOT NULL
               GROUP BY cover_id ORDER BY COUNT(*) DESC LIMIT 4""", (name,))]
        featured.append({"name": name, "display_name": state["playlist_names"].get(name, name),
                         "track_count": tot, "from_album": n_in, "covers": covers,
                         "has_cover": (COVERS_DIR / f"{_safe_name(name)}.jpg").exists()})
    # …and the album artists' Essentials (the page decides which artists qualify, same rule as the Artists page)
    ess = [dict(r) for r in db.execute(
        f"""SELECT COALESCE(album_artist,artist) AS name, COUNT(DISTINCT album) AS album_count, COUNT(*) AS track_count,
                   MIN(cover_id) AS cover_id FROM tracks
            WHERE COALESCE(album_artist,artist) IN ({','.join('?' * len(artists))}) GROUP BY name""", artists)] if artists else []
    forced = {n.lower() for n in state["forced_essentials"]}
    for e in ess:
        e["forced"] = e["name"].lower() in forced
    # More from the album's artist(s)
    more = [dict(r) for r in db.execute(
        f"""SELECT {_ALBUM_COLS} FROM tracks
            WHERE COALESCE(album_artist,artist) IN ({','.join('?' * len(artists))}) AND album<>? AND album IS NOT NULL AND album<>''
            GROUP BY album ORDER BY MAX(year) DESC, album""", artists + [album])] if artists else []
    # You may also like: other artists' albums sharing a genre, nudged by era and popularity
    keys = {_genre_parts(r["genre"])[0] for r in rows} - {None}
    years = [r["year"] for r in rows if r["year"]]
    yr = sorted(years)[len(years) // 2] if years else None
    plays = {r[0]: r[1] for r in db.execute("SELECT track_id, COUNT(*) FROM plays GROUP BY track_id")}
    cand: dict = {}
    for r in db.execute("SELECT id,album,genre,year,COALESCE(album_artist,artist) AS a FROM tracks "
                        "WHERE album IS NOT NULL AND album<>'' AND album<>?", (album,)):
        if r["a"] in artists:
            continue
        c = cand.setdefault(r["album"], {"genre": 0, "plays": 0, "years": []})
        if _genre_parts(r["genre"])[0] in keys:
            c["genre"] += 1
        c["plays"] += plays.get(r["id"], 0)
        if r["year"]:
            c["years"].append(r["year"])
    def score(c):
        era = 0
        if yr and c["years"]:
            gap = abs(sorted(c["years"])[len(c["years"]) // 2] - yr)
            era = 2 if gap <= 5 else 1 if gap <= 12 else 0
        return (c["genre"] > 0) * 10 + era + min(c["plays"], 50) / 25
    picks = [a for a, c in sorted(cand.items(), key=lambda kv: -score(kv[1]))][:12]   # genre matches rank first
    like = []
    if picks:
        got = {r["album"]: dict(r) for r in db.execute(
            f"SELECT {_ALBUM_COLS} FROM tracks WHERE album IN ({','.join('?' * len(picks))}) GROUP BY album", picks)}
        like = [got[a] for a in picks if a in got]
    db.close()
    # Generated playlists on the Search category pages (genres and decades) that include this album's songs
    ids = {r["id"] for r in rows}
    category = []
    pages = [("genre", k) for k in sorted(keys)] + [("decade", d) for d in sorted({(y // 10) * 10 for y in years}, reverse=True)]
    for kind, key in pages:
        try:
            page = api_genre_page(key) if kind == "genre" else api_decade_page(key)
        except HTTPException:
            continue
        for pl in page["playlists"]:
            n = sum(1 for t in pl["tracks"] if t["id"] in ids)
            if n:
                category.append({**pl, "from_album": n, "category": page["label"], "kind": kind, "key": key})
    category.sort(key=lambda p: -p["from_album"])
    return {"artists": artists, "featured": featured, "essentials": ess, "category": category[:12],
            "brand": state["name"], "more": more, "like": like}

# ── Profiles & friends ────────────────────────────────────────────────────────
def init_profiles_db():
    db = get_db()
    cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
    for col, decl in (("display_name", "TEXT"), ("bio", "TEXT DEFAULT ''"), ("avatar", "TEXT DEFAULT ''"),
                      ("activity_vis", "TEXT DEFAULT 'friends'"), ("show_top", "INTEGER DEFAULT 1"),
                      ("likes_public", "INTEGER DEFAULT 0"), ("profile_done", "INTEGER DEFAULT 0")):
        if col not in cols:
            db.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS friends (
            user_id INTEGER NOT NULL, friend_id INTEGER NOT NULL, status TEXT NOT NULL, created REAL,
            PRIMARY KEY (user_id, friend_id)
        );
    """)
    db.commit(); db.close()

init_profiles_db()
_VIS = ("everyone", "friends", "private")

def _me_user(req: Request) -> dict:
    """Profiles and friends are for user accounts only."""
    u = _session_user(req)
    if not u or u["id"] == 0:
        raise HTTPException(401, "Log in with your own account to use profiles and friends")
    return u

def _relation(db, me: int, other: int) -> str:
    if me == other:
        return "self"
    a = db.execute("SELECT status FROM friends WHERE user_id=? AND friend_id=?", (me, other)).fetchone()
    b = db.execute("SELECT status FROM friends WHERE user_id=? AND friend_id=?", (other, me)).fetchone()
    if a and b:
        return "friends"
    if a:
        return "outgoing"
    if b:
        return "incoming"
    return "none"

def _friend_ids(db, uid: int) -> list:
    return [r[0] for r in db.execute(
        """SELECT f.friend_id FROM friends f JOIN friends g ON g.user_id=f.friend_id AND g.friend_id=f.user_id
           WHERE f.user_id=?""", (uid,))]

def _can_see_activity(rel: str, vis: str) -> bool:
    return rel == "self" or vis == "everyone" or (vis == "friends" and rel == "friends")

def _user_card(r) -> dict:
    return {"username": r["username"], "display_name": r["display_name"] or r["username"], "avatar": r["avatar"] or ""}

def _now_playing(db, uid: int):
    r = db.execute(f"""SELECT {_TRACK_SEL}, p.played_at FROM plays p JOIN tracks t ON t.id=p.track_id
                       WHERE p.user_id=? ORDER BY p.played_at DESC LIMIT 1""", (uid,)).fetchone()
    if r and _now() - r["played_at"] < 15 * 60:          # logged ~30s into a song, so recent = probably still playing
        return dict(r)
    return None

@api.get("/api/me/profile")
def api_my_profile(req: Request):
    u = _me_user(req)
    db = get_db()
    r = db.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    pls = [{"id": p["id"], "name": p["name"], "shared": bool(p["shared"])}
           for p in db.execute("SELECT id,name,shared FROM user_playlists WHERE user_id=? ORDER BY updated DESC", (u["id"],))]
    db.close()
    return {"username": r["username"], "display_name": r["display_name"] or "", "bio": r["bio"] or "",
            "avatar": r["avatar"] or "", "activity_vis": r["activity_vis"] or "friends", "show_top": bool(r["show_top"]),
            "likes_public": bool(r["likes_public"]), "profile_done": bool(r["profile_done"]), "playlists": pls}

@api.patch("/api/me/profile")
async def api_edit_profile(req: Request):
    u = _me_user(req)
    body = await req.json()
    db = get_db()
    try:
        if "username" in body:
            name = str(body["username"] or "").strip()
            if not _USERNAME_RE.match(name) or name.lower() == "admin":
                raise HTTPException(400, "Username: 2–32 letters, numbers, dots, dashes or underscores")
            clash = db.execute("SELECT id FROM users WHERE username=? AND id<>?", (name, u["id"])).fetchone()
            if clash:
                raise HTTPException(400, "That username is taken")
            db.execute("UPDATE users SET username=? WHERE id=?", (name, u["id"]))
        if "display_name" in body:
            db.execute("UPDATE users SET display_name=? WHERE id=?", (re.sub(r"\s+", " ", str(body["display_name"] or "")).strip()[:40], u["id"]))
        if "bio" in body:
            db.execute("UPDATE users SET bio=? WHERE id=?", (str(body["bio"] or "").strip()[:200], u["id"]))
        if "avatar" in body:
            av = str(body["avatar"] or "")
            if av and not (av.startswith("data:image/jpeg;base64,") and len(av) < 200_000):
                raise HTTPException(400, "Profile photo must be a JPEG under 150 KB")
            db.execute("UPDATE users SET avatar=? WHERE id=?", (av, u["id"]))
        if "activity_vis" in body:
            if body["activity_vis"] not in _VIS:
                raise HTTPException(400, "activity_vis must be everyone, friends or private")
            db.execute("UPDATE users SET activity_vis=? WHERE id=?", (body["activity_vis"], u["id"]))
        for k in ("show_top", "likes_public", "profile_done"):
            if k in body:
                db.execute(f"UPDATE users SET {k}=? WHERE id=?", (1 if body[k] else 0, u["id"]))
        if isinstance(body.get("public_playlists"), list):   # ids of the playlists to show on the profile
            show = {int(i) for i in body["public_playlists"] if str(i).isdigit()}
            for (pid,) in db.execute("SELECT id FROM user_playlists WHERE user_id=?", (u["id"],)).fetchall():
                db.execute("UPDATE user_playlists SET shared=? WHERE id=?", (1 if pid in show else 0, pid))
        db.commit()
    finally:
        db.close()
    return api_my_profile(req)

@api.get("/api/users")
def api_users_directory(req: Request, q: str = ""):
    me = _me_user(req)
    db = get_db()
    like = f"%{q.strip()}%"
    rows = db.execute("""SELECT id,username,display_name,avatar FROM users
                         WHERE id<>? AND (username LIKE ? OR COALESCE(display_name,'') LIKE ?)
                         ORDER BY COALESCE(display_name,username) COLLATE NOCASE LIMIT 50""", (me["id"], like, like)).fetchall()
    out = [{**_user_card(r), "relation": _relation(db, me["id"], r["id"])} for r in rows]
    db.close()
    return out

@api.get("/api/users/{username}")
def api_profile(username: str, req: Request):
    me = _me_user(req)
    db = get_db()
    r = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not r:
        db.close(); raise HTTPException(404, "No one by that name")
    uid = r["id"]
    rel = _relation(db, me["id"], uid)
    see = _can_see_activity(rel, r["activity_vis"] or "friends")
    out = {**_user_card(r), "bio": r["bio"] or "", "relation": rel, "activity_hidden": not see,
           "friends": [_user_card(f) for f in db.execute(
               f"SELECT username,display_name,avatar FROM users WHERE id IN ({','.join('?' * len(fids))})", fids)]
           if (fids := _friend_ids(db, uid)) else [],
           "playlists": [_pl_summary(db, p, me["id"]) for p in db.execute(
               "SELECT * FROM user_playlists WHERE user_id=? AND shared=1 ORDER BY updated DESC", (uid,))],
           "likes_public": bool(r["likes_public"]) or rel == "self",
           "likes_count": db.execute("SELECT COUNT(*) FROM likes WHERE user_id=?", (uid,)).fetchone()[0]
           if (r["likes_public"] or rel == "self") else None,
           "now": None, "recent": [], "top_artists": [], "top_songs": []}
    if see:
        out["now"] = _now_playing(db, uid)
        seen, recent = set(), []
        for t in db.execute(f"""SELECT {_TRACK_SEL}, p.played_at FROM plays p JOIN tracks t ON t.id=p.track_id
                                WHERE p.user_id=? ORDER BY p.played_at DESC LIMIT 200""", (uid,)):
            if t["id"] not in seen:
                seen.add(t["id"]); recent.append(dict(t))
            if len(recent) >= 16:
                break
        out["recent"] = recent
        if r["show_top"] or rel == "self":
            st = _rewind_stats(_user_plays(db, uid, _now() - 30 * 86400, _now() + 1), 10)
            out["top_artists"], out["top_songs"], out["month_minutes"] = st["top_artists"][:8], st["top_songs"], st["minutes"]
    db.close()
    return out

@api.get("/api/users/{username}/likes")
def api_profile_likes(username: str, req: Request):
    me = _me_user(req)
    db = get_db()
    r = db.execute("SELECT id,likes_public FROM users WHERE username=?", (username,)).fetchone()
    if not r or not (r["likes_public"] or r["id"] == me["id"]):
        db.close(); raise HTTPException(404, "Not shared")
    rows = [dict(x) for x in db.execute(
        f"SELECT {_TRACK_SEL} FROM likes l JOIN tracks t ON t.id=l.track_id WHERE l.user_id=? ORDER BY l.created DESC", (r["id"],))]
    db.close()
    return {"tracks": rows}

@api.get("/api/me/friends")
def api_friends(req: Request):
    me = _me_user(req)
    db = get_db()
    def cards(ids, with_now=False):
        out = []
        for uid in ids:
            r = db.execute("SELECT id,username,display_name,avatar,activity_vis FROM users WHERE id=?", (uid,)).fetchone()
            if not r:
                continue
            c = _user_card(r)
            if with_now and _can_see_activity("friends", r["activity_vis"] or "friends"):
                c["now"] = _now_playing(db, uid)
            out.append(c)
        return out
    friends = _friend_ids(db, me["id"])
    mine = {r[0] for r in db.execute("SELECT friend_id FROM friends WHERE user_id=?", (me["id"],))}
    theirs = {r[0] for r in db.execute("SELECT user_id FROM friends WHERE friend_id=?", (me["id"],))}
    res = {"friends": cards(friends, True), "incoming": cards(sorted(theirs - mine)), "outgoing": cards(sorted(mine - theirs))}
    db.close()
    return res

@api.post("/api/me/friends/{username}")
def api_friend_add(username: str, req: Request):
    """Send a request, or accept theirs (both rows present = friends)."""
    me = _me_user(req)
    db = get_db()
    r = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not r or r["id"] == me["id"]:
        db.close(); raise HTTPException(404, "No one by that name")
    db.execute("INSERT OR IGNORE INTO friends(user_id,friend_id,status,created) VALUES(?,?,?,?)", (me["id"], r["id"], "ok", _now()))
    db.commit(); rel = _relation(db, me["id"], r["id"]); db.close()
    return {"relation": rel}

@api.delete("/api/me/friends/{username}")
def api_friend_remove(username: str, req: Request):
    """Unfriend, cancel a request, or decline one: removes both directions."""
    me = _me_user(req)
    db = get_db()
    r = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if r:
        db.execute("DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)",
                   (me["id"], r["id"], r["id"], me["id"]))
        db.commit()
    db.close()
    return {"relation": "none"}

def _friends_mix(db, uid: int, mk):
    """Songs your friends have been playing lately (only friends who share their listening with friends)."""
    names, counts, who = [], {}, {}
    for fid in _friend_ids(db, uid):
        f = db.execute("SELECT username,display_name,activity_vis FROM users WHERE id=?", (fid,)).fetchone()
        if not f or not _can_see_activity("friends", f["activity_vis"] or "friends"):
            continue
        name = f["display_name"] or f["username"]
        got = False
        for (tid,) in db.execute("SELECT track_id FROM plays WHERE user_id=? AND played_at>? ORDER BY played_at DESC LIMIT 400",
                                 (fid, _now() - 21 * 86400)):
            counts[tid] = counts.get(tid, 0) + 1
            who.setdefault(tid, set()).add(name); got = True
        if got:
            names.append(name)
    if not names:
        return None
    ids = sorted(counts, key=lambda t: (-len(who[t]), -counts[t]))[:40]
    who_txt = (names[0] if len(names) == 1 else f"{names[0]} and {names[1]}" if len(names) == 2
               else f"{names[0]}, {names[1]} and {len(names) - 2} more")
    sub = f"What {who_txt} {'has' if len(names) == 1 else 'have'} been playing"
    m = mk("friends", "Friends Mix", ids, sub)
    if m:
        for t in m["tracks"]:
            t["friends"] = sorted(who.get(t["id"], []))
        m["artists"] = names[:5]                       # the card footer lists friends instead of artists
    return m

# ── Explicit tags & admin accounts ────────────────────────────────────────────
_EXPLICIT_TITLE = re.compile(r"[\(\[]\s*explicit\s*[\)\]]", re.I)

def _explicit_flag(path: Path, title: str = "") -> int:
    """1 if the file is marked explicit (iTunes rating, ITUNESADVISORY / EXPLICIT tags, or '(Explicit)' in the title)."""
    try:
        af = MutagenFile(str(path))
        tags = getattr(af, "tags", None) if af is not None else None
        if tags is not None:
            rt = tags.get("rtng") if hasattr(tags, "get") else None          # MP4/M4A: 1 or 4 = explicit, 2 = clean
            if rt:
                v = rt[0] if isinstance(rt, list) else rt
                if int(v) in (1, 4):
                    return 1
            for k in list(tags.keys()):                                       # ID3 TXXX frames + Vorbis comments
                kl = str(k).lower()
                if any(x in kl for x in ("itunesadvisory", "explicit", "contentrating", "advisory")):
                    v = tags[k]
                    v = getattr(v, "text", v)
                    v = str(v[0] if isinstance(v, list) and v else v).strip().lower()
                    if v in ("1", "4", "explicit", "true", "yes", "e"):
                        return 1
    except Exception:
        pass
    return 1 if _EXPLICIT_TITLE.search(title or path.stem) else 0

def _init_explicit():
    db = get_db()
    cols = {r[1] for r in db.execute("PRAGMA table_info(tracks)")}
    if cols and "explicit" not in cols:
        db.execute("ALTER TABLE tracks ADD COLUMN explicit INTEGER")
        db.commit()
    ucols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
    if ucols and "is_admin" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        db.commit()
    db.close()

def _backfill_explicit():
    """Existing libraries: read the explicit flag once for tracks scanned before this feature."""
    _init_explicit()
    db = get_db()
    try:
        rows = db.execute("SELECT id,path,title FROM tracks WHERE explicit IS NULL").fetchall()
    except sqlite3.OperationalError:        # no library yet
        db.close(); return
    for n, r in enumerate(rows):
        db.execute("UPDATE tracks SET explicit=? WHERE id=?", (_explicit_flag(Path(r["path"]), r["title"]), r["id"]))
        if n % 200 == 199:
            db.commit()
    db.commit(); db.close()

_init_explicit()
threading.Thread(target=_backfill_explicit, daemon=True).start()

@api.get("/api/explicit")
def api_explicit_ids():
    db = get_db()
    ids = [r[0] for r in db.execute("SELECT id FROM tracks WHERE explicit=1")]
    db.close()
    return {"ids": ids}

@api.post("/api/admin/users/{uid}/admin")
async def api_users_set_admin(uid: int, req: Request):
    _require_admin(req)
    on = bool((await req.json()).get("admin"))
    db = get_db(); db.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if on else 0, uid)); db.commit(); db.close()
    return {"admin": on}

def _admin_cli(args: list) -> int:
    """python leon_music.py admin list | add <user> | remove <user> | create <user>"""
    for _s in (sys.stdout, sys.stderr):              # old Windows consoles: never crash on ✓ / ★
        try: _s.reconfigure(errors="replace")
        except Exception: pass
    init_db(); init_users_db(); init_profiles_db(); _init_explicit()
    cmd = (args[0] if args else "help").lower()
    db = get_db()
    try:
        if cmd == "list":
            rows = db.execute("SELECT username,is_admin FROM users ORDER BY username COLLATE NOCASE").fetchall()
            if not rows:
                print("No user accounts yet. Create one with:  admin create <username>")
            for r in rows:
                print(f"  {'★ admin ' if r['is_admin'] else '        '}{r['username']}")
            print("\n  (the built-in 'admin' login always works with the admin password)")
            return 0
        if cmd in ("add", "remove") and len(args) == 2:
            r = db.execute("SELECT id,username FROM users WHERE username=?", (args[1],)).fetchone()
            if not r:
                print(f"No account called '{args[1]}'. Run 'admin list' to see accounts, or 'admin create {args[1]}'.")
                return 1
            db.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if cmd == "add" else 0, r["id"])); db.commit()
            print(f"✓ {r['username']} is {'now an admin' if cmd == 'add' else 'no longer an admin'}. "
                  f"{'They get admin controls the next time they open leon.music.' if cmd == 'add' else ''}")
            return 0
        if cmd == "create" and len(args) == 2:
            import getpass
            name = args[1]
            if not _USERNAME_RE.match(name) or name.lower() == "admin":
                print("Username: 2–32 letters, numbers, dots, dashes or underscores (not 'admin').")
                return 1
            if db.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
                print(f"'{name}' already exists. To make them an admin:  admin add {name}")
                return 1
            pw = getpass.getpass(f"Password for {name} (8+ characters): ")
            if len(pw) < MIN_PW_LEN or pw != getpass.getpass("Repeat password: "):
                print("Passwords didn't match or were too short. Nothing changed.")
                return 1
            db.execute("INSERT INTO users(username,pw_hash,is_admin) VALUES(?,?,1)", (name, _hash_pw(pw))); db.commit()
            print(f"✓ Created admin account '{name}'. Note: logins are now required for everyone on this server.")
            return 0
        print(__doc__ if False else
              "leon.music admin commands:\n"
              "  python leon_music.py admin list               show accounts (★ = admin)\n"
              "  python leon_music.py admin add <username>     make an existing account an admin\n"
              "  python leon_music.py admin remove <username>  take admin rights away\n"
              "  python leon_music.py admin create <username>  create a new admin account (asks for a password)")
        return 0 if cmd == "help" else 1
    finally:
        db.close()

# ── Admin page ────────────────────────────────────────────────────────────────
ADMIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>leon.music — Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d0d0f;--bg2:#1a1a1e;--bg3:#222226;--bg4:#2a2a30;--fg:#f0f0f2;--fg2:#a0a0ac;--fg3:#606068;--accent:#e5282a;--border:#2a2a30;--radius:12px}
body{background:var(--bg);color:var(--fg);font-family:'Montserrat',sans-serif;min-height:100vh;display:flex;flex-direction:column}
header{padding:20px 32px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border)}
.logo{display:flex;align-items:center;gap:8px;font-size:16px;font-weight:900;letter-spacing:-.5px}
.logo-dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.logo a{color:var(--fg);text-decoration:none}
.badge{font-size:10px;background:var(--bg4);color:var(--fg3);padding:3px 8px;border-radius:20px;font-weight:600}
main{flex:1;max-width:600px;margin:40px auto;width:100%;padding:0 20px}
h1{font-size:22px;font-weight:900;margin-bottom:28px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:28px;margin-bottom:20px}
.card-title{font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:20px}
label{display:block;font-size:12px;font-weight:600;color:var(--fg2);margin-bottom:6px;margin-top:16px}
label:first-of-type{margin-top:0}
input,select{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:11px 14px;font-family:inherit;font-size:13px;font-weight:500;color:var(--fg);transition:border-color .2s;outline:none}
input:focus,select:focus{border-color:var(--accent)}
input::placeholder{color:var(--fg3)}
.row{display:flex;gap:12px;margin-top:20px}
.btn{padding:11px 20px;border-radius:8px;border:none;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;transition:all .15s}
.btn-primary{background:var(--accent);color:#fff;flex:1}
.btn-primary:hover{background:#c82022}
.btn-secondary{background:var(--bg4);color:var(--fg2)}
.btn-secondary:hover{background:var(--bg3)}
.msg{font-size:12px;margin-top:12px;min-height:16px}
.msg.ok{color:#4caf50}.msg.err{color:var(--accent)}
#loginWrap{display:flex;align-items:center;justify-content:center;flex:1;min-height:60vh}
.login-card{background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:40px;width:100%;max-width:360px}
.login-title{font-size:20px;font-weight:900;margin-bottom:6px}
.login-sub{font-size:13px;color:var(--fg2);margin-bottom:24px}
.swatches{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.sw{width:30px;height:30px;border-radius:50%;border:2px solid transparent;cursor:pointer;padding:0}
.sw.sel{border-color:var(--fg);box-shadow:inset 0 0 0 2px var(--bg2)}
input[type=color]{width:44px;height:34px;padding:2px;border-radius:8px;cursor:pointer}
input[type=checkbox]{width:auto}
.chk{display:flex;align-items:center;gap:10px;margin-top:16px;font-size:12px;font-weight:600;color:var(--fg2)}
.chk span{flex:1}
.hero-prev{--ht:#e5282a;position:relative;height:110px;border-radius:12px;overflow:hidden;margin-top:16px;background:#1a1a1a;display:flex;align-items:flex-end;padding:16px}
.hero-prev img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:none}
.hero-prev.has-img img{display:block}
.hero-shade{position:absolute;inset:0;background:radial-gradient(ellipse at 75% 40%,color-mix(in srgb,var(--ht) 22%,transparent) 0%,transparent 65%),linear-gradient(135deg,color-mix(in srgb,var(--ht) 18%,#000) 0%,#1a1a1a 65%)}
.hero-prev.has-img .hero-shade{background:linear-gradient(0deg,rgba(0,0,0,.55) 0%,transparent 65%),linear-gradient(100deg,color-mix(in srgb,var(--ht) 78%,#000) 0%,color-mix(in srgb,var(--ht) 50%,transparent) 55%,color-mix(in srgb,var(--ht) 28%,transparent) 100%)}
.hero-prev .t{position:relative;font-weight:900;font-size:18px;letter-spacing:-.5px;color:#fff}
.cv-tabs{display:flex;gap:8px;margin-bottom:12px}
.cv-tabs .btn.on{background:var(--accent);color:#fff}
.cv-prev{position:relative;width:220px;max-width:100%;aspect-ratio:1;border-radius:12px;overflow:hidden;
  background:linear-gradient(135deg,#3a3a42,#1c1c20);user-select:none;touch-action:none}
#cvArt{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:none;padding:0;border:0;border-radius:0}
.cv-prev.has-art #cvArt{display:block}
.cv-tint{position:absolute;inset:0;background:linear-gradient(0deg,rgba(0,0,0,.45) 0%,transparent 55%),color-mix(in srgb,var(--accent) 55%,transparent)}
.cv-prev.pl .cv-tint{background:linear-gradient(0deg,rgba(0,0,0,.65),rgba(0,0,0,.2))}
.cv-label{position:absolute;left:12px;bottom:10px;font-weight:900;font-size:15px;letter-spacing:-.3px;color:#fff;text-shadow:0 1px 6px rgba(0,0,0,.4)}
.cv-prev.pl .cv-label{left:50%;top:50%;bottom:auto;transform:translate(-50%,-50%);font-size:22px;letter-spacing:0;text-transform:uppercase}
.cv-prev.pl.tp-top .cv-label{top:14%;transform:translate(-50%,0)}
.cv-prev.pl.tp-bottom .cv-label{top:auto;bottom:14%;transform:translate(-50%,0)}
.cv-wrap{display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start;margin-top:12px}
.snap-grid{display:grid;grid-template-columns:repeat(3,34px);gap:6px}
.snap-grid button{width:34px;height:34px;padding:0;border-radius:8px;border:none;background:var(--bg4);cursor:pointer;position:relative}
.snap-grid button:hover{background:var(--bg3)}
.snap-grid button::after{content:"";position:absolute;width:8px;height:8px;border-radius:50%;background:var(--fg2);top:50%;left:50%;transform:translate(-50%,-50%)}
.snap-grid button.tl::after{top:7px;left:7px;transform:none}.snap-grid button.tc::after{top:7px}
.snap-grid button.tr::after{top:7px;left:auto;right:7px;transform:none}.snap-grid button.ml::after{left:7px;transform:translateY(-50%)}
.snap-grid button.mr::after{left:auto;right:7px;transform:translateY(-50%)}
.snap-grid button.bl::after{top:auto;bottom:7px;left:7px;transform:none}.snap-grid button.bc::after{top:auto;bottom:7px}
.snap-grid button.br::after{top:auto;bottom:7px;left:auto;right:7px;transform:none}
.cv-side{flex:1;min-width:200px}
.cv-side label{margin-top:12px}.cv-side label:first-child{margin-top:0}
#pvLogo{position:absolute;transform:translate(-50%,-50%);height:auto;max-height:40%;object-fit:contain;
  cursor:grab;filter:drop-shadow(0 1px 4px rgba(0,0,0,.45));touch-action:none;padding:0;border:0;border-radius:0;background:none}
#pvLogo.drag{cursor:grabbing;outline:1px dashed rgba(255,255,255,.7)}
.cv-ctl{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.cv-empty{font-size:11px;color:var(--fg3);margin-top:8px;min-height:14px}
.st-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)}
.st-info{flex:1;min-width:0}
.st-name{font-size:13px;font-weight:700}
.st-url{font-size:11px;color:var(--fg3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style>
</head>
<body>
<header>
  <div class="logo"><div class="logo-dot"></div><a href="/">leon.music</a></div>
  <div style="display:flex;align-items:center;gap:12px">
    <button class="btn btn-secondary" id="logoutBtn" style="display:none;padding:6px 12px;font-size:11px" onclick="doLogout()">Log out</button>
    <div class="badge">Admin</div>
  </div>
</header>

<div id="loginWrap">
  <div class="login-card">
    <div class="login-title">Admin login</div>
    <div class="login-sub">Enter your admin password to continue.</div>
    <label>Password</label>
    <input type="password" id="pw" placeholder="Your admin password" onkeydown="if(event.key==='Enter')doLogin()">
    <div class="msg err" id="loginErr"></div>
    <div class="row" style="margin-top:16px">
      <button class="btn btn-primary" onclick="doLogin()">Sign in →</button>
    </div>
  </div>
</div>

<main id="adminMain" style="display:none">
  <h1>Settings</h1>

  <div class="card">
    <div class="card-title">Logo</div>
    <label>Logo image URL (shown on Essentials and playlist covers)</label>
    <input type="url" id="logoUrl" placeholder="https://example.com/logo.png" oninput="updateCoverPreview()">

    <label>Cover logo placement</label>
    <div class="cv-tabs">
      <button class="btn btn-secondary on" id="tabEss" onclick="setPvMode('ess')">Essentials</button>
      <button class="btn btn-secondary" id="tabPl" onclick="setPvMode('pl')">Playlist</button>
    </div>
    <div class="chk" style="margin-top:0"><input type="checkbox" id="clEnabled" onchange="setCl('enabled',this.checked)">
      <span id="clEnabledLbl">Show the logo on Essentials covers</span></div>
    <div class="cv-wrap">
      <div>
        <div class="cv-prev ess" id="cvPrev">
          <img id="cvArt" alt="">
          <div class="cv-tint"></div>
          <div class="cv-label" id="cvLabel">Essentials</div>
          <img id="pvLogo" alt="" draggable="false" style="display:none">
        </div>
        <div class="cv-empty" id="cvHint"></div>
      </div>
      <div class="cv-side">
        <label>Snap to</label>
        <div class="snap-grid">
          <button class="tl" title="Top left" onclick="snapLogo(0,0)"></button>
          <button class="tc" title="Top center" onclick="snapLogo(50,0)"></button>
          <button class="tr" title="Top right" onclick="snapLogo(100,0)"></button>
          <button class="ml" title="Middle left" onclick="snapLogo(0,50)"></button>
          <button class="mc" title="Center" onclick="snapLogo(50,50)"></button>
          <button class="mr" title="Middle right" onclick="snapLogo(100,50)"></button>
          <button class="bl" title="Bottom left" onclick="snapLogo(0,100)"></button>
          <button class="bc" title="Bottom center" onclick="snapLogo(50,100)"></button>
          <button class="br" title="Bottom right" onclick="snapLogo(100,100)"></button>
        </div>
        <label>Or drag the logo in the preview</label>
        <div class="cv-ctl" style="margin-top:0">
          <button class="btn btn-secondary" id="clCopy" onclick="copyCl()">Copy to Playlist</button>
          <button class="btn btn-secondary" onclick="resetCl()">Reset</button>
        </div>
      </div>
    </div>
    <label>Horizontal position <span id="clXVal"></span></label>
    <input type="range" id="clX" min="0" max="100" step="0.5" style="padding:0" oninput="setCl('x',+this.value)">
    <label>Vertical position <span id="clYVal"></span></label>
    <input type="range" id="clY" min="0" max="100" step="0.5" style="padding:0" oninput="setCl('y',+this.value)">
    <label>Logo size <span id="clSizeVal"></span></label>
    <input type="range" id="clSize" min="8" max="60" step="1" style="padding:0" oninput="setCl('size',+this.value)">
    <label>Opacity <span id="clOpacityVal"></span></label>
    <input type="range" id="clOpacity" min="10" max="100" step="1" style="padding:0" oninput="setCl('opacity',+this.value)">
    <div class="chk"><input type="checkbox" id="clInside" onchange="setCl('inside',this.checked)">
      <span>Keep the logo fully inside the cover (never cut off at the edges)</span></div>
    <div class="chk"><input type="checkbox" id="clShadow" onchange="setCl('shadow',this.checked)">
      <span>Drop shadow behind the logo</span></div>
    <div class="chk"><input type="checkbox" id="clWhite" onchange="setCl('white',this.checked)">
      <span>Force the logo to white (helps dark logos stand out)</span></div>
    <div id="txtPosWrap" style="display:none">
      <label>Playlist name position on generated covers</label>
      <select id="txtPos" onchange="_txtPos=this.value;updateCoverPreview()">
        <option value="top">Top</option>
        <option value="center">Center</option>
        <option value="bottom">Bottom</option>
      </select>
      <div class="cv-empty">Applies to newly generated covers. Open a playlist and regenerate its cover to update it.</div>
    </div>
    <div class="msg" id="logoMsg"></div>
    <div class="row">
      <button class="btn btn-primary" onclick="saveLogo()">Save logo</button>
      <button class="btn btn-secondary" onclick="clearLogo()">Clear</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Theme</div>
    <label>Accent color</label>
    <div class="swatches"><span id="swatches" style="display:contents"></span>
      <input type="color" id="accentCustom" title="Custom color" oninput="pickAccent(this.value)"></div>
    <label>Hero banner image URL</label>
    <input type="url" id="heroUrl" placeholder="https://example.com/photo.jpg" oninput="previewHero()">
    <div class="chk"><input type="checkbox" id="tintCustomOn" onchange="previewHero()">
      <span>Use a different color for the banner shade</span>
      <input type="color" id="tintCustom" value="#e5282a" oninput="document.getElementById('tintCustomOn').checked=true;previewHero()"></div>
    <div class="hero-prev" id="heroPrev"><img id="heroImg" alt=""><div class="hero-shade"></div><div class="t">leon.music</div></div>
    <div class="msg" id="themeMsg"></div>
    <div class="row">
      <button class="btn btn-primary" onclick="saveTheme()">Save theme</button>
      <button class="btn btn-secondary" onclick="clearHero()">Remove image</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Artists</div>
    <div class="chk" style="margin-top:0"><input type="checkbox" id="picsOnline" onchange="savePicsOnline()">
      <span>Fetch artist photos from Deezer automatically. Artist names are sent to deezer.com; you can also set a photo by URL on any artist page.</span></div>
    <div class="chk"><input type="checkbox" id="lyricsOnline" onchange="saveLyricsOnline()">
      <span>Look up lyrics on LRCLIB (lrclib.net) when a song has no .lrc file or embedded lyrics. Artist, title, album and length are sent to lrclib.net; results are saved, so each song is looked up once.</span></div>
    <div class="msg" id="picsMsg"></div>
    <label>Force an Essentials page</label>
    <div style="display:flex;gap:8px">
      <input type="text" id="forceName" list="artistList" placeholder="Start typing an artist in your library"
             onkeydown="if(event.key==='Enter')addForced()">
      <datalist id="artistList"></datalist>
      <button class="btn btn-secondary" onclick="addForced()">Add</button>
    </div>
    <div class="msg" id="forceMsg"></div>
    <div id="forcedList"></div>
  </div>

  <div class="card">
    <div class="card-title">Release years</div>
    <div style="font-size:12.5px;color:var(--fg2);line-height:1.5">Looks up release years on Deezer for songs that don't have one in their tags.
      Years power the Decades categories on the Search page. Artist and song names are sent to deezer.com.</div>
    <div id="ysInfo" style="font-size:13px;font-weight:700;margin:14px 0 10px">…</div>
    <div id="ysBarWrap" style="display:none;height:8px;border-radius:99px;background:var(--bg4);overflow:hidden;margin-bottom:10px">
      <div id="ysBar" style="height:100%;width:0;background:var(--accent);transition:width .3s"></div></div>
    <button class="btn btn-primary" id="ysBtn" onclick="startYearScan()">Scan for release years</button>
    <div class="msg" id="ysMsg"></div>
  </div>

  <div class="card">
    <div class="card-title">Radio stations</div>
    <div id="stList"></div>
    <label>Station name</label>
    <input type="text" id="stName" placeholder="Radio Paradise">
    <label>Stream URL</label>
    <input type="url" id="stUrl" placeholder="https://stream.example.com/mount.mp3">
    <label>Logo URL (optional)</label>
    <input type="url" id="stLogo" placeholder="https://example.com/logo.png">
    <label>Metadata URL (optional)</label>
    <input type="url" id="stMeta" placeholder="Icecast status-json.xsl, auto-detected if blank">
    <div class="msg" id="stMsg"></div>
    <div class="row">
      <button class="btn btn-primary" onclick="addStation()">Add station</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Security</div>
    <label>New admin password (min. 8 characters)</label>
    <input type="password" id="newPw" placeholder="Leave blank to keep current">
    <label>Confirm password</label>
    <input type="password" id="newPw2" placeholder="">
    <div class="msg" id="pwMsg"></div>
    <div class="row">
      <button class="btn btn-primary" onclick="savePw()">Change password</button>
    </div>
    <label style="margin-top:28px">Library password (optional)</label>
    <div class="cv-empty" id="libPwState" style="margin:0 0 8px"></div>
    <input type="password" id="libPw" placeholder="Visitors must enter this to browse and stream">
    <div class="msg" id="libPwMsg"></div>
    <div class="row">
      <button class="btn btn-primary" onclick="saveLibPw()">Set library password</button>
      <button class="btn btn-secondary" onclick="clearLibPw()">Remove</button>
    </div>
  </div>
</main>

<script>
let _token = localStorage.getItem('adminToken') || '';

async function doLogin(){
  const pw = document.getElementById('pw').value;
  const r = await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  if(!r.ok){const e = await r.json().catch(()=>({}));document.getElementById('loginErr').textContent = e.detail || 'Wrong password.';return;}
  const d = await r.json();
  _token = d.token;
  localStorage.setItem('adminToken', _token);
  showAdmin();
}

function doLogout(){
  localStorage.removeItem('adminToken'); _token = '';
  location.href = '/';
}

async function showAdmin(){
  const r = await fetch('/api/admin/settings',{headers:{'X-Admin-Token':_token}});
  if(!r.ok){_token='';localStorage.removeItem('adminToken');document.getElementById('loginErr').textContent='Session expired, please sign in again.';return;}
  const d = await r.json();
  document.getElementById('logoUrl').value = d.logo_url || '';
  showLibPwState(!!d.has_library_password);
  const cfg = d.cover_logo_cfg || {};
  _cl = {ess: {...LOGO_DEF, ...(cfg.ess || {})}, pl: {...LOGO_DEF, ...(cfg.pl || {})}};
  _txtPos = d.cover_text_pos || 'center';
  document.getElementById('txtPos').value = _txtPos;
  updateCoverPreview();
  loadThemeUI(d);
  loadForcedUI(d);
  loadStations();
  loadYearScan();
  document.getElementById('loginWrap').style.display = 'none';
  document.getElementById('adminMain').style.display = 'block';
  document.getElementById('logoutBtn').style.display = '';
}

let _ysTimer=null;
async function loadYearScan(){
  let s;try{s=await (await fetch('/api/years/scan/status',{headers:{'X-Admin-Token':_token}})).json();}catch(e){return;}
  const info=document.getElementById('ysInfo'),btn=document.getElementById('ysBtn'),wrap=document.getElementById('ysBarWrap');
  if(s.running){
    wrap.style.display='';document.getElementById('ysBar').style.width=(s.total?Math.round(s.done/s.total*100):3)+'%';
    info.textContent=`Scanning… ${s.done} / ${s.total} songs · ${s.found} years found`;
    btn.disabled=true;btn.textContent='Scanning…';
    clearTimeout(_ysTimer);_ysTimer=setTimeout(loadYearScan,1500);
  }else{
    clearTimeout(_ysTimer);wrap.style.display=s.done?'':'none';
    if(s.done)document.getElementById('ysBar').style.width='100%';
    info.textContent=s.missing?`${s.missing} of ${s.library} songs have no release year`:`All ${s.library} songs have a release year ✓`;
    btn.disabled=!s.missing;btn.textContent=s.done?'Scan again':'Scan for release years';
    if(s.done&&s.total){const m=document.getElementById('ysMsg');m.className='msg ok';m.textContent=`Last scan found ${s.found} of ${s.total} years.`;}
  }
}
async function startYearScan(){
  const m=document.getElementById('ysMsg');m.textContent='';
  const r=await fetch('/api/years/scan',{method:'POST',headers:{'X-Admin-Token':_token}});
  if(!r.ok){m.className='msg err';m.textContent='Could not start the scan.';return;}
  setTimeout(loadYearScan,400);
}

async function saveLogo(){
  const r = await fetch('/api/admin/settings',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-Admin-Token':_token},
    body:JSON.stringify({logo_url:document.getElementById('logoUrl').value.trim(),
                         cover_logo_cfg:_cl, cover_text_pos:_txtPos})
  });
  const m = document.getElementById('logoMsg');
  if(r.ok){m.className='msg ok';m.textContent='Saved ✓';}
  else{m.className='msg err';m.textContent='Failed to save.';}
  setTimeout(()=>m.textContent='',3000);
}

function clearLogo(){
  document.getElementById('logoUrl').value='';
  updateCoverPreview();
}

async function savePw(){
  const p1 = document.getElementById('newPw').value;
  const p2 = document.getElementById('newPw2').value;
  const m = document.getElementById('pwMsg');
  if(!p1){m.className='msg err';m.textContent='Enter a password.';return;}
  if(p1!==p2){m.className='msg err';m.textContent='Passwords do not match.';return;}
  const r = await fetch('/api/admin/settings',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-Admin-Token':_token},
    body:JSON.stringify({admin_password:p1})
  });
  if(r.ok){m.className='msg ok';m.textContent='Password updated ✓';}
  else{const e = await r.json().catch(()=>({}));m.className='msg err';m.textContent = e.detail || 'Failed.';}
  document.getElementById('newPw').value='';
  document.getElementById('newPw2').value='';
  setTimeout(()=>m.textContent='',3000);
}

async function postSettings(body){
  return fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':_token},body:JSON.stringify(body)});
}
function showLibPwState(on){
  document.getElementById('libPwState').textContent = on ? 'A library password is set.' : 'No library password: anyone who can reach this server can browse and stream.';
}
async function saveLibPw(){
  const v = document.getElementById('libPw').value, m = document.getElementById('libPwMsg');
  if(!v){m.className='msg err';m.textContent='Enter a password.';return;}
  const r = await postSettings({library_password:v});
  if(r.ok){m.className='msg ok';m.textContent='Library password set ✓';showLibPwState(true);document.getElementById('libPw').value='';}
  else{const e = await r.json().catch(()=>({}));m.className='msg err';m.textContent = e.detail || 'Failed.';}
  setTimeout(()=>m.textContent='',3000);
}
async function clearLibPw(){
  const m = document.getElementById('libPwMsg');
  const r = await postSettings({clear_library_password:true});
  m.className = r.ok ? 'msg ok' : 'msg err'; m.textContent = r.ok ? 'Library password removed ✓' : 'Failed.';
  if(r.ok) showLibPwState(false);
  setTimeout(()=>m.textContent='',3000);
}

// ── Theme ──
const PRESETS = [['Red','#e5282a'],['Orange','#f97316'],['Green','#22c55e'],['Blue','#3b82f6'],['Purple','#8b5cf6'],['Pink','#ec4899']];
let _accent = '#e5282a';

function renderSwatches(){
  const box = document.getElementById('swatches');
  box.innerHTML = '';
  PRESETS.forEach(([n,c]) => {
    const b = document.createElement('button');
    b.className = 'sw' + (c.toLowerCase() === _accent.toLowerCase() ? ' sel' : '');
    b.style.background = c; b.title = n;
    b.onclick = () => pickAccent(c);
    box.appendChild(b);
  });
  document.getElementById('accentCustom').value = _accent;
}
function pickAccent(c){
  _accent = c;
  document.documentElement.style.setProperty('--accent', c);
  renderSwatches();
  previewHero();
}
function previewHero(){
  const url = document.getElementById('heroUrl').value.trim();
  const box = document.getElementById('heroPrev');
  const img = document.getElementById('heroImg');
  const tint = document.getElementById('tintCustomOn').checked ? document.getElementById('tintCustom').value : _accent;
  box.style.setProperty('--ht', tint);
  if(url){ img.onload = () => box.classList.add('has-img'); img.onerror = () => box.classList.remove('has-img'); if(img.getAttribute('src') !== url) img.src = url; }
  else { box.classList.remove('has-img'); img.removeAttribute('src'); }
}
function loadThemeUI(d){
  _accent = d.accent || '#e5282a';
  document.getElementById('picsOnline').checked = d.artist_pics_online !== false;
  document.getElementById('lyricsOnline').checked = d.lyrics_online !== false;
  document.documentElement.style.setProperty('--accent', _accent);
  document.getElementById('heroUrl').value = d.hero_image || '';
  document.getElementById('tintCustomOn').checked = !!d.hero_tint;
  if(d.hero_tint) document.getElementById('tintCustom').value = d.hero_tint;
  renderSwatches();
  previewHero();
}
function clearHero(){ document.getElementById('heroUrl').value = ''; previewHero(); }
async function saveTheme(){
  const body = {
    accent: _accent,
    hero_image: document.getElementById('heroUrl').value.trim(),
    hero_tint: document.getElementById('tintCustomOn').checked ? document.getElementById('tintCustom').value : ''
  };
  const r = await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':_token},body:JSON.stringify(body)});
  const m = document.getElementById('themeMsg');
  if(r.ok){ m.className = 'msg ok'; m.textContent = 'Saved ✓ — reload the player to see it'; }
  else { const e = await r.json().catch(() => ({})); m.className = 'msg err'; m.textContent = e.detail || 'Failed to save.'; }
  setTimeout(() => m.textContent = '', 4000);
}

// ── Artist photos ──
async function saveLyricsOnline(){
  const on = document.getElementById('lyricsOnline').checked;
  const r = await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':_token},body:JSON.stringify({lyrics_online:on})});
  const m = document.getElementById('picsMsg');
  m.className = r.ok ? 'msg ok' : 'msg err';
  m.textContent = r.ok ? 'Saved ✓' : 'Failed to save.';
  setTimeout(() => m.textContent = '', 3000);
}
async function savePicsOnline(){
  const on = document.getElementById('picsOnline').checked;
  const r = await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':_token},body:JSON.stringify({artist_pics_online:on})});
  const m = document.getElementById('picsMsg');
  m.className = r.ok ? 'msg ok' : 'msg err';
  m.textContent = r.ok ? 'Saved ✓' : 'Failed to save.';
  setTimeout(() => m.textContent = '', 3000);
}

// ── Cover logo placement: one profile per cover type (centre point + width, in % of the cover) ──
const LOGO_DEF = {enabled:true, x:18, y:14, size:26, opacity:95, shadow:true, white:false, inside:true};
let _cl = {ess: {...LOGO_DEF}, pl: {...LOGO_DEF}};
let _txtPos = 'center';
let _pvMode = 'ess';
const MODE_NAME = {ess: 'Essentials', pl: 'Playlist'};
const _clampN = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const _r1 = v => Math.round(v * 10) / 10;

// Where the logo really ends up. With "keep inside" on, the centre is limited so the whole logo
// (its real width and height) stays 3% away from every edge. The same maths runs on the player.
function effPos(c, img){
  if(!c.inside) return {x: c.x, y: c.y};
  const w = c.size, ar = (img && img.naturalWidth) ? img.naturalHeight / img.naturalWidth : 0.5;
  const h = Math.min(w * ar, 40), m = 3;
  return {x: _r1(_clampN(c.x, w/2 + m, 100 - w/2 - m)), y: _r1(_clampN(c.y, h/2 + m, 100 - h/2 - m))};
}
function setPvMode(m){
  _pvMode = m;
  const box = document.getElementById('cvPrev');
  box.classList.toggle('ess', m === 'ess'); box.classList.toggle('pl', m === 'pl');
  document.getElementById('tabEss').classList.toggle('on', m === 'ess');
  document.getElementById('tabPl').classList.toggle('on', m === 'pl');
  updateCoverPreview();
}
function setCl(key, val){ _cl[_pvMode][key] = val; updateCoverPreview(); }
function snapLogo(fx, fy){
  const c = _cl[_pvMode], e = effPos({...c, x: fx, y: fy, inside: true}, document.getElementById('pvLogo'));
  c.x = e.x; c.y = e.y; updateCoverPreview();
}
function copyCl(){
  const other = _pvMode === 'ess' ? 'pl' : 'ess';
  _cl[other] = {..._cl[_pvMode]};
  const h = document.getElementById('cvHint');
  h.textContent = 'Copied to ' + MODE_NAME[other] + ' covers.';
  setTimeout(updateCoverPreview, 2500);
}
function resetCl(){ _cl[_pvMode] = {...LOGO_DEF}; updateCoverPreview(); }
function updateCoverPreview(){
  const url = document.getElementById('logoUrl').value.trim();
  const c = _cl[_pvMode], name = MODE_NAME[_pvMode];
  const lg = document.getElementById('pvLogo'), box = document.getElementById('cvPrev');
  if(url && lg.getAttribute('src') !== url){ lg.onload = updateCoverPreview; lg.src = url; }
  const e = effPos(c, lg);
  lg.style.left = e.x + '%'; lg.style.top = e.y + '%'; lg.style.width = c.size + '%';
  lg.style.opacity = c.opacity / 100;
  lg.style.filter = (c.white ? 'brightness(0) invert(1) ' : '') + (c.shadow ? 'drop-shadow(0 1px 4px rgba(0,0,0,.45))' : '');
  lg.style.display = (url && c.enabled) ? '' : 'none';
  // controls mirror the profile being edited (sliders show where the logo actually sits)
  document.getElementById('clEnabled').checked = c.enabled;
  document.getElementById('clEnabledLbl').textContent = 'Show the logo on ' + name + ' covers';
  document.getElementById('clX').value = e.x;           document.getElementById('clXVal').textContent = e.x + '%';
  document.getElementById('clY').value = e.y;           document.getElementById('clYVal').textContent = e.y + '%';
  document.getElementById('clSize').value = c.size;     document.getElementById('clSizeVal').textContent = c.size + '%';
  document.getElementById('clOpacity').value = c.opacity; document.getElementById('clOpacityVal').textContent = c.opacity + '%';
  document.getElementById('clInside').checked = c.inside;
  document.getElementById('clShadow').checked = c.shadow;
  document.getElementById('clWhite').checked = c.white;
  document.getElementById('clCopy').textContent = 'Copy to ' + (_pvMode === 'ess' ? 'Playlist' : 'Essentials');
  document.getElementById('cvLabel').textContent = name;
  box.classList.remove('tp-top', 'tp-center', 'tp-bottom');
  if(_pvMode === 'pl') box.classList.add('tp-' + _txtPos);
  document.getElementById('txtPosWrap').style.display = _pvMode === 'pl' ? '' : 'none';
  document.getElementById('cvHint').textContent = !url ? 'Add a logo image URL above to place it.'
    : (!c.enabled ? 'Off: ' + name + ' covers will not show the logo.' : '');
}
function loadPreviewArt(list){
  const top = list.filter(a => !/^(unknown artist|various artists)$/i.test(a.name)).sort((a,b) => b.track_count - a.track_count)[0];
  if(!top) return;
  const img = document.getElementById('cvArt'), box = document.getElementById('cvPrev');
  img.onload = () => box.classList.add('has-art');
  img.onerror = () => box.classList.remove('has-art');
  img.src = '/api/artist/pic?name=' + encodeURIComponent(top.name);
}
(function(){
  const lg = document.getElementById('pvLogo'), box = document.getElementById('cvPrev');
  let drag = false;
  lg.addEventListener('pointerdown', e => { drag = true; lg.setPointerCapture(e.pointerId); lg.classList.add('drag'); e.preventDefault(); });
  lg.addEventListener('pointermove', e => {
    if(!drag) return;
    const r = box.getBoundingClientRect(), c = _cl[_pvMode];
    c.x = _r1(_clampN((e.clientX - r.left) / r.width * 100, 0, 100));
    c.y = _r1(_clampN((e.clientY - r.top) / r.height * 100, 0, 100));
    const eff = effPos(c, lg); c.x = eff.x; c.y = eff.y;
    updateCoverPreview();
  });
  const end = () => { drag = false; lg.classList.remove('drag'); };
  lg.addEventListener('pointerup', end); lg.addEventListener('pointercancel', end);
})();

// ── Forced Essentials ──
let _forced = [];
let _artistNames = {};
async function loadForcedUI(d){
  _forced = d.forced_essentials || [];
  renderForced();
  try{
    const list = await (await fetch('/api/artists',{headers:{'X-Admin-Token':_token}})).json();
    const dl = document.getElementById('artistList');
    dl.innerHTML = ''; _artistNames = {};
    loadPreviewArt(list);
    list.forEach(a => {
      _artistNames[a.name.toLowerCase()] = a.name;
      const o = document.createElement('option'); o.value = a.name; dl.appendChild(o);
    });
  }catch(e){}
}
function renderForced(){
  const box = document.getElementById('forcedList');
  box.innerHTML = '';
  _forced.forEach(n => {
    const row = document.createElement('div'); row.className = 'st-row';
    const info = document.createElement('div'); info.className = 'st-info';
    const t = document.createElement('div'); t.className = 'st-name'; t.textContent = n + ' Essentials';
    info.appendChild(t);
    const del = document.createElement('button'); del.className = 'btn btn-secondary'; del.textContent = 'Remove';
    del.onclick = () => { _forced = _forced.filter(x => x !== n); renderForced(); saveForced(); };
    row.append(info, del);
    box.appendChild(row);
  });
}
async function saveForced(){
  const m = document.getElementById('forceMsg');
  const r = await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':_token},body:JSON.stringify({forced_essentials:_forced})});
  m.className = r.ok ? 'msg ok' : 'msg err';
  m.textContent = r.ok ? 'Saved ✓' : (r.status === 401 ? 'Session expired — reload and sign in again.' : 'Failed to save.');
  setTimeout(() => m.textContent = '', 3000);
}
function addForced(){
  const inp = document.getElementById('forceName');
  const m = document.getElementById('forceMsg');
  const v = inp.value.trim();
  if(!v) return;
  const canon = _artistNames[v.toLowerCase()];
  if(!canon){ m.className = 'msg err'; m.textContent = 'No artist with that name in your library.'; return; }
  if(!_forced.some(x => x.toLowerCase() === canon.toLowerCase())) _forced.push(canon);
  inp.value = '';
  renderForced();
  saveForced();
}

// ── Radio ──
async function loadStations(){
  const box = document.getElementById('stList');
  try{
    const list = await (await fetch('/api/radio/stations',{headers:{'X-Admin-Token':_token}})).json();
    box.innerHTML = '';
    if(!list.length){ const e = document.createElement('div'); e.className = 'st-url'; e.style.padding = '4px 0 8px'; e.textContent = 'No stations yet.'; box.appendChild(e); return; }
    list.forEach(s => {
      const row = document.createElement('div'); row.className = 'st-row';
      const info = document.createElement('div'); info.className = 'st-info';
      const n = document.createElement('div'); n.className = 'st-name'; n.textContent = s.name;
      const u = document.createElement('div'); u.className = 'st-url'; u.textContent = s.url;
      info.append(n, u);
      const del = document.createElement('button'); del.className = 'btn btn-secondary'; del.textContent = 'Remove';
      del.onclick = () => removeStation(s.id, s.name);
      row.append(info, del);
      box.appendChild(row);
    });
  }catch(e){ box.textContent = 'Could not load stations.'; }
}
async function addStation(){
  const m = document.getElementById('stMsg');
  const body = {
    name: document.getElementById('stName').value,
    url: document.getElementById('stUrl').value,
    logo: document.getElementById('stLogo').value,
    meta_url: document.getElementById('stMeta').value
  };
  const r = await fetch('/api/admin/radio',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':_token},body:JSON.stringify(body)});
  if(r.ok){
    ['stName','stUrl','stLogo','stMeta'].forEach(id => document.getElementById(id).value = '');
    m.className = 'msg ok'; m.textContent = 'Station added ✓';
    loadStations();
  } else {
    const e = await r.json().catch(() => ({}));
    m.className = 'msg err'; m.textContent = r.status === 401 ? 'Session expired — reload and sign in again.' : (e.detail || 'Failed.');
  }
  setTimeout(() => m.textContent = '', 4000);
}
async function removeStation(id, name){
  if(!confirm('Remove ' + name + '?')) return;
  await fetch('/api/admin/radio/' + id,{method:'DELETE',headers:{'X-Admin-Token':_token}});
  loadStations();
}

// Auto-login if token already in session, or if this login is an admin account
if(_token) showAdmin();
else fetch('/api/admin/check').then(r=>r.json()).then(d=>{if(d.admin)showAdmin();}).catch(()=>{});
</script>
</body>
</html>"""

@api.get("/admin", response_class=HTMLResponse)
def serve_admin():
    return HTMLResponse(ADMIN_HTML)

@api.get("/", response_class=HTMLResponse)
def serve_frontend():
    if FRONTEND_PATH.exists():
        return HTMLResponse(FRONTEND_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(f"<html><body style='font:14px system-ui;padding:40px;background:#111;color:#eee'>"
                        f"<h1>leon.music</h1><p>Place frontend.html next to this file.</p>"
                        f"<p><a href='/api/status' style='color:#e5282a'>/api/status</a></p></body></html>")

# ── Server thread ─────────────────────────────────────────────────────────────
_server_started = threading.Event()

def _run_server():
    config = _uvicorn.Config(api, host="127.0.0.1", port=PORT,
                              log_level="warning", loop="asyncio")
    server = _uvicorn.Server(config)
    _server_started.set()
    server.run()

# ── Tray ──────────────────────────────────────────────────────────────────────
_tray_icon: Optional[object] = None

def _open_browser(_icon=None, _item=None):
    webbrowser.open(f"http://localhost:{PORT}")

def _do_rescan(_icon=None, _item=None):
    if not state["scanning"]:
        threading.Thread(target=scan_library, daemon=True).start()

def _do_quit(_icon=None, _item=None):
    if _tray_icon:
        _tray_icon.stop()
    os._exit(0)

def _build_menu():
    return _pystray.Menu(
        _pystray.MenuItem("Open leon.music", _open_browser, default=True),
        _pystray.MenuItem("Rescan library",  _do_rescan),
        _pystray.Menu.SEPARATOR,
        _pystray.MenuItem(f"http://localhost:{PORT}", None, enabled=False),
        _pystray.Menu.SEPARATOR,
        _pystray.MenuItem("Quit", _do_quit),
    )

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global _tray_icon
    if len(sys.argv) > 1 and sys.argv[1].lower() == "admin":     # python leon_music.py admin add <username>
        sys.exit(_admin_cli(sys.argv[2:]))

    # Init DB
    init_db()

    # Start server thread
    t = threading.Thread(target=_run_server, daemon=True)
    t.start()
    _server_started.wait(timeout=5)

    # Initial scan only if setup has been completed (music_dir saved in config)
    if cfg.get("music_dir") and state["music_dir"].exists():
        threading.Thread(target=scan_library, daemon=True).start()

    # Open browser (first run or always)
    def _delayed_open():
        sleep(1.2)
        webbrowser.open(f"http://localhost:{PORT}")
    threading.Thread(target=_delayed_open, daemon=True).start()

    print(f"  leon.music running on http://localhost:{PORT}")
    print(f"  Music folder: {state['music_dir']}")
    print(f"  Close the tray icon to quit.\n")

    # Run tray (blocks main thread — required on macOS)
    icon_img = _make_icon(64)
    _tray_icon = _pystray.Icon(
        "leon.music", icon_img,
        f"leon.music — {PORT}",
        menu=_build_menu(),
    )
    _tray_icon.run()

if __name__ == "__main__":
    main()
