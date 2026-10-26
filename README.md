# leon.music

A self-hosted music player that lives in your system tray. Point it at a folder and you're streaming from your browser in seconds. No cloud, no accounts, no subscriptions.

- **One folder = your library.** Top-level subfolders automatically become playlists.
- **Streams to any browser** with HTTP range support, so seeking works.
- **Reads tags and embedded cover art** from MP3, FLAC, M4A/AAC, OGG, Opus, WAV and WMA.
- **Artist pages and "Essentials"** mixes, with artist photos fetched from Deezer (optional).
- **Internet radio** for Icecast and Shoutcast streams, with live "now playing".
- **Admin panel** for theming, cover logos, playlist covers, radio stations and more.
- **Light and dark themes**, responsive layout, mobile friendly.
- Just two files: `leon_music.py` (server and tray app) and `frontend.html` (the player UI).

## Quick start

Requires Python 3.9+.

```bash
git clone https://github.com/<your-username>/leon-music.git
cd leon-music
pip install -r requirements.txt
python leon_music.py
```

A tray icon appears and your browser opens to <http://localhost:7733>. The welcome wizard asks for:

1. Your music folder
2. A name for your library
3. An optional admin password

Then it scans your library and you're ready to play.

> On some systems you may need `pip install -r requirements.txt --break-system-packages`.
> On Linux, `pystray` needs an appindicator/GTK backend for the tray icon (for example `sudo apt install gir1.2-appindicator3-0.1`).

## How your library is organised

```
Music/
├── latenight/          ← becomes the "latenight" playlist
│   ├── track1.mp3
│   └── track2.flac
├── workout/            ← becomes the "workout" playlist
│   └── ...
└── loose-song.mp3      ← in the library, but not in a playlist
```

- Only the **first-level folder** name is used as the playlist.
- Albums, artists and songs come from the **file tags**, not the folder layout.
- Renaming a playlist in the UI changes only its display name. Your files never move.
- Artists with 6 or more tracks automatically get an **Essentials** page. Admins can force one for any artist.

Rescan from the tray menu ("Rescan library") or from Settings in the web UI. Unchanged files are skipped, so rescans are quick.

## Admin panel

Open <http://localhost:7733/admin> (or "Admin login" in Settings).

- **Logo and covers**: place your logo on Essentials and playlist covers (drag, snap, size, opacity, shadow).
- **Theme**: accent colour, hero banner image and tint.
- **Artists**: toggle online photo lookup, force Essentials pages, set custom artist photos by URL.
- **Radio**: add and remove stations (stream URL, optional logo and metadata URL).
- **Security**: change the admin password.

Playlist covers are generated from an image URL with the playlist name overlaid. Open a playlist while logged in as admin and use the Cover button. Playlist renaming is available in the same place.

## Internet radio

Add a station in the admin panel with its stream URL. Now-playing info is read from Icecast's `status-json.xsl` when available, and otherwise from in-stream ICY metadata (Shoutcast v1/v2 and Icecast). If you serve the player over HTTPS and a stream is plain HTTP, the server relays it to avoid mixed-content blocking.

## Configuration and data

Everything is stored in `~/.leon-music/`:

| Path | Contents |
| --- | --- |
| `config.json` | Library path, name, theme, admin password, radio stations, cover settings |
| `library.db` | SQLite index of your tracks and embedded covers |
| `playlist-covers/` | Generated playlist covers |
| `artist-pics/` | Cached or custom artist photos |

Your music files are only ever read, never modified. To start over, delete the folder.

The server listens on `127.0.0.1:7733`. Change `PORT` near the top of `leon_music.py` if needed.

## Accessing it from other devices

By default leon.music only listens on localhost. To use it from your phone or elsewhere, put it behind a reverse proxy (Caddy, nginx, Tailscale Serve, Cloudflare Tunnel, etc.) with HTTPS. **Set an admin password first**; see the security notes below.

## Building a standalone app

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "leon.music" leon_music.py
```

Place `frontend.html` **next to the built executable**; it is loaded from disk at runtime. The same command works on Windows (`.exe`) and macOS (`.app`).

## API overview

All endpoints are under `/api`. Admin endpoints need an `X-Admin-Token` header obtained from `POST /api/admin/login`.

| Endpoint | Description |
| --- | --- |
| `GET /api/status` | Library name, counts, scan progress, theme |
| `GET /api/tracks` | Tracks (filter by `album`, `artist`, `playlist`, `search`) |
| `GET /api/albums`, `/api/artists`, `/api/playlists` | Browse the library |
| `GET /api/stream/{id}` | Audio stream with range support |
| `GET /api/cover/{id}` | Embedded cover art |
| `GET /api/artist/pic?name=` | Artist photo |
| `GET /api/radio/stations`, `/api/radio/{id}/now` | Radio |
| `POST /api/admin/*`, `POST /api/playlist/{name}/*` | Admin actions |

## Security notes

leon.music is built for personal, trusted-network use. Before exposing it to the internet, be aware that:

- **Set an admin password during setup.** If none is set, anyone who can reach the server can log in as admin.
- The library itself (browsing and streaming) is **not password protected**. Only admin actions are.
- Admin actions that fetch URLs (playlist covers, artist photos) make requests from your machine, so do not give admin access to people you don't trust.
- Artist photo lookup sends artist names to deezer.com. Turn it off in the admin panel if you'd rather not.

Found a vulnerability? Please open a private security advisory on GitHub rather than a public issue.

## Contributing

Issues and pull requests are welcome. The project is intentionally small and dependency-light, so please keep changes focused. Ideas that would be great to have:

- Hashed admin passwords and optional library login
- Playlists you can edit (not just folder based)
- Search across albums and artists
- Gapless playback and queue management
- Docker image

## License

[MIT](LICENSE)

## Credits

Built with [FastAPI](https://fastapi.tiangolo.com/), [Uvicorn](https://www.uvicorn.org/), [Mutagen](https://mutagen.readthedocs.io/), [Pillow](https://python-pillow.org/) and [pystray](https://github.com/moses-palmer/pystray). Artist photos via the [Deezer API](https://developers.deezer.com/).
