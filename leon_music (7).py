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
        _, salt, want = stored.split("$")
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
    """)
    db.commit()
    db.close()

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
               "/api/admin/login", "/api/admin/check"}

def _lib_locked() -> bool:
    return bool(load_config().get("library_password_hash"))

def _has_access(req: Request) -> bool:
    if not _lib_locked():
        return True
    return req.cookies.get("lm_session", "") in _sessions or _is_admin(req)

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
    return bool(token) and token in _admin_tokens

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
    return next((s for s in _stations() if s.get("id") == sid), None)

@api.get("/api/radio/stations")
def api_radio_stations():
    return [{"id": s["id"], "name": s["name"], "url": s["url"], "logo": s.get("logo", "")}
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
  document.getElementById('loginWrap').style.display = 'none';
  document.getElementById('adminMain').style.display = 'block';
  document.getElementById('logoutBtn').style.display = '';
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

// Auto-login if token already in session
if(_token) showAdmin();
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
