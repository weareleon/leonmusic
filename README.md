# leon.music

**🌐 Website & docs: [weareleon.github.io/leonmusic](https://weareleon.github.io/leonmusic/)**

A self-hosted music player that lives in your system tray. Point it at a folder and you're streaming from your browser in seconds. No cloud, no subscriptions.

- **One folder = your library.** Top-level subfolders automatically become playlists.
- **Streams to any browser** with HTTP range support, so seeking works.
- **Reads tags and embedded cover art** from MP3, FLAC, M4A/AAC, OGG, Opus, WAV and WMA.
- **Artist pages and "Essentials"** mixes, with artist photos fetched from Deezer (optional).
- **Internet radio** for Icecast and Shoutcast streams, with live "now playing".
- **Your own live radio stations**, broadcast to your Icecast server on a schedule you set.
- **User accounts** with a personal "Made for You" home, Top Picks and **Rewind** listening stats.
- **Charts, a New page, Search with genre and decade categories.**
- **Likes, your own playlists, synced lyrics, profiles and friends**, with a Friends Mix.
- **Admin panel** for theming, cover logos, playlist covers, radio stations and more.
- **Light and dark themes**, responsive layout, mobile friendly.
- Just two files: `leon_music.py` (server and tray app) and `frontend.html` (the player UI).

## What's new in 2.2

- **🎄 Christmas category**: a Christmas tile in Search (first in line from mid-November to early January) with everything Christmas on your server, special playlists (Christmas Classics, Cozy Christmas, Christmas Party, New Christmas Music) and your Holiday station when it's on air.
- **🖼 Playlist cover designer**: design covers for your own playlists, and admins for folder playlists, with your own photo, gradients, overlays, title and subtitle styling, and any font installed on the server's computer.
- **Fixed**: deprecation warnings and `WinError 10054` noise in the console on Windows, and unclosed-file warnings when skipping songs.

## What's new in 2.1

- **♥ Likes & your own playlists**: heart songs into Liked Songs, create playlists from any song's ··· menu, drag to reorder, and share them with everyone on the server.
- **🎤 Synced lyrics**: tap **Ly** in the player for full-screen lyrics that follow the song. They come from `.lrc` files next to your songs, lyrics in your tags, or [LRCLIB](https://lrclib.net), a free and open lyrics database (switchable in the admin panel).
- **👤 Profiles & friends**: a profile setup wizard (photo, name, which playlists to show, privacy), public profiles with *Listening now* and top artists, friend requests, and a **Friends Mix** in Made for You.
- **💿 Album pages**: *Featured On* (Essentials, folder playlists, and genre and decade playlists), *More from …* and *You May Also Like*.
- **🅴 Explicit badges** read from your tags, and live radio stations that can skip explicit songs.
- **🛡 Admin accounts**: make any account an admin from Settings or with `python leon_music.py admin add <username>`.
- **Fixed**: cover logos were cropped on square mix covers.

## The Biggest Music Update (2.0)

- **Search page** with results for songs, artists and albums, plus *Browse categories*: a tinted tile for every genre on your server and a **Decades** row. Each genre and decade has its own page with feature cards, generated playlists, top songs, albums and artists.
- **New page**: feature cards, newest songs, trending songs, new albums, new and updated playlists, this year's releases and new artists. Albums, Artists and Songs now live at the bottom of this page.
- **Charts**: the server counts plays (after ~30 seconds of listening) and builds weekly, monthly and all-time Top 50, genre and artist charts, with rank movement and generated chart covers.
- **Live radio**: an admin setup wizard to create your own stations (ready-made ones like *1, Hits, Club, Chill, Holiday* or custom ones with their own logo), schedule which playlists play when (including timed shows with custom covers), connect Icecast, and go live. Each station has a schedule page. Stations reconnect on their own if Icecast restarts.
- **User accounts**: admins create accounts in Settings. New users pick the genres they like and get a personal mix. The home page shows **Made for You** mixes (New Music, Heavy Rotation, Your Essentials, Get Up!, Chill) and **Top Picks for You** once there's enough listening history.
- **Rewind**: a Weekly Rewind (minutes, top artists and songs, day-by-day chart, new discoveries), a full Rewind by year and month, a Rewind playlist for every year, and an End of Year Rewind in December.
- **Release-year scan** moved to the admin panel.

## Quick start

Requires Python 3.9+. Live radio uses [ffmpeg](https://ffmpeg.org/) (on your PATH or next to the app) to broadcast every audio format; without it, only MP3 files can be broadcast.

```bash
git clone https://github.com/weareleon/leonmusic
cd leonmusic
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

## Admin accounts

Besides the built-in `admin` login, any user account can be an admin. Run these from the folder with `leon_music.py`:

```bash
python leon_music.py admin list              # accounts, ★ = admin
python leon_music.py admin add alex          # make an account an admin
python leon_music.py admin remove alex       # take it away again
python leon_music.py admin create someone    # new admin account (asks for a password)
```

Or use **Make admin** in Settings → Users.

## Admin panel

Open <http://localhost:7733/admin> (or "Admin login" in Settings).

- **Logo and covers**: place your logo on Essentials and playlist covers (drag, snap, size, opacity, shadow).
- **Theme**: accent colour, hero banner image and tint.
- **Artists**: toggle online photo lookup, force Essentials pages, set custom artist photos by URL.
- **Radio**: add and remove stations (stream URL, optional logo and metadata URL).
- **Release years**: look up missing release years on Deezer (used by the Decades categories).
- **Security**: change the admin password.

Playlist covers are generated from an image URL with the playlist name overlaid. Open a playlist while logged in as admin and use the Cover button. Playlist renaming is available in the same place.

## User accounts and logins

Admins add accounts under **Settings → Users** (passwords are 8+ characters and stored as salted scrypt hashes). As soon as the first account exists, or a library password is set, everyone has to log in:

- **Users** log in with their username and password.
- **The admin** logs in on the same screen with the username `admin` and the admin password.
- **The shared library password** (if set) still works: leave the username blank.

Listening history is per account and powers Heavy Rotation, Top Picks and Rewind. Logins are rate-limited.

## Live radio

Admins open **Radio → Set up live radio** to:

1. Pick stations from templates or design custom ones (name, colours, logo style). The *Holiday* station plays exactly one Christmas playlist.
2. Choose each station's normal rotation and add shows for specific days and times.
3. Enter the Icecast host, port and **source** password (the `<source-password>` from `icecast.xml`), with a *Test connection* button.
4. Go live and watch each station connect.

Each station streams 128–320 kbps MP3 to its own Icecast mount and updates the song title on every track. If Icecast's address is `localhost`, listeners on other devices are relayed through leon.music automatically.

## Internet radio

Add a station in the admin panel with its stream URL. Now-playing info is read from Icecast's `status-json.xsl` when available, and otherwise from in-stream ICY metadata (Shoutcast v1/v2 and Icecast). If you serve the player over HTTPS and a stream is plain HTTP, the server relays it to avoid mixed-content blocking.

## Configuration and data

Everything is stored in `~/.leon-music/`:

| Path | Contents |
| --- | --- |
| `config.json` | Library path, name, theme, password hashes, radio stations, live-radio setup (incl. Icecast source password), cover settings |
| `library.db` | SQLite index of your tracks and embedded covers, plays, user accounts and sessions |
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
| `GET /api/search?q=`, `/api/genres`, `/api/genres/{key}`, `/api/decades` | Search and categories |
| `GET /api/charts?period=week\|month\|all` | Charts |
| `GET /api/new` | New page |
| `POST /api/auth/login`, `GET /api/auth/me` | Logins (accounts, admin, library password) |
| `GET /api/me/home`, `/api/me/rewind`, `/api/me/rewind/week` | Personal mixes and Rewind |
| `/api/me/likes`, `/api/me/playlists` | Liked Songs and your playlists |
| `GET /api/lyrics/{id}` | Lyrics |
| `/api/me/profile`, `/api/users/{name}`, `/api/me/friends` | Profiles and friends |
| `GET/POST /api/broadcast` | Live radio setup (admin) |
| `POST /api/admin/*`, `POST /api/playlist/{name}/*` | Admin actions |

## Security notes

leon.music is built for personal, trusted-network use. Before exposing it to the internet, be aware that:

- **Set an admin password during setup.** If none is set, anyone who can reach the server can log in as admin.
- The library is open to anyone who can reach it **until** you set a library password or create the first user account.
- Admin actions that fetch URLs (playlist covers, artist photos) make requests from your machine, so do not give admin access to people you don't trust.
- Artist photo lookup sends artist names to deezer.com. Turn it off in the admin panel if you'd rather not. The release-year scan sends artist and song names to deezer.com too, and lyrics lookup sends artist, title, album and length to lrclib.net (also switchable).
- Profiles share listening with friends only by default; each person can choose everyone or only themselves.
- The Icecast source password is stored in `config.json` (so stations can reconnect on their own); it is never sent back to the browser.

Found a vulnerability? Please open a private security advisory on GitHub rather than a public issue.

## Contributing

Issues and pull requests are welcome. The project is intentionally small and dependency-light, so please keep changes focused. Ideas that would be great to have:

- Playlists you can edit (not just folder based)
- Gapless playback and queue management
- Docker image

## License

[MIT](LICENSE)

## Credits

Built with [FastAPI](https://fastapi.tiangolo.com/), [Uvicorn](https://www.uvicorn.org/), [Mutagen](https://mutagen.readthedocs.io/), [Pillow](https://python-pillow.org/) and [pystray](https://github.com/moses-palmer/pystray). Artist photos via the [Deezer API](https://developers.deezer.com/).
