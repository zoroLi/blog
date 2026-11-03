import base64
import html
import mimetypes
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import urllib.parse
from datetime import datetime
from functools import wraps
from pathlib import Path

import bleach
import markdown as markdown_lib
from bleach.css_sanitizer import CSSSanitizer
from bs4 import BeautifulSoup
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markdownify import markdownify
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _load_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    key_file = INSTANCE_DIR / "secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    DATABASE=str(INSTANCE_DIR / "blog.db"),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
    PER_PAGE=10,
)
app.json.ensure_ascii = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    content_format TEXT NOT NULL DEFAULT 'text',
    section_id INTEGER REFERENCES sections(id) ON DELETE SET NULL,
    is_shared INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'published',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);

CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_post_tags_tag ON post_tags(tag_id);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);

CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS post_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_post ON post_history(post_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_history_create
    ON post_history(post_id) WHERE action = 'create';
"""

USERNAME_RE = re.compile(r"^[^\s/\\]{1,20}$")
IMAGE_MD_RE = re.compile(r"!\[([^\]\n]*)\]\(((?:https?://|/)[^)\s]+)\)")
ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

ALLOWED_POST_TAGS = [
    "p", "br", "div", "span", "strong", "b", "em", "i", "u", "s",
    "strike", "del", "ins", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "blockquote", "a", "img", "pre", "code", "hr",
    "sub", "sup", "font", "table", "thead", "tbody", "tr", "th", "td",
]
def _allow_code_class(tag: str, name: str, value: str) -> bool:
    if name != "class" or tag not in ("code", "pre"):
        return False
    parts = value.split()
    return bool(parts) and all(
        re.fullmatch(r"language-[A-Za-z0-9_+#.-]+", part) for part in parts
    )


ALLOWED_POST_ATTRS = {
    "a": ["href", "title", "target", "rel"],
    "img": ["src", "alt", "title", "width", "height"],
    "font": ["size", "face", "color"],
    "code": _allow_code_class,
    "pre": _allow_code_class,
    "th": ["colspan", "rowspan"],
    "td": ["colspan", "rowspan"],
    "*": ["style"],
}
CSS_SANITIZER = CSSSanitizer(
    allowed_css_properties=[
        "color",
        "background-color",
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "text-align",
        "text-decoration",
        "text-decoration-line",
        "line-height",
    ]
)


def normalize_code_html(html_text: str) -> str:
    if "<pre" not in html_text.lower():
        return html_text

    soup = BeautifulSoup(html_text, "html.parser")
    changed = False
    for pre in soup.find_all("pre"):
        for br in pre.find_all("br"):
            br.replace_with("\n")
            changed = True
        for tag in pre.find_all(["div", "p"]):
            tag.append("\n")
            tag.unwrap()
            changed = True
    return str(soup) if changed else html_text


def sanitize_post_html(raw: str) -> str:
    return bleach.clean(
        normalize_code_html(raw),
        tags=ALLOWED_POST_TAGS,
        attributes=ALLOWED_POST_ATTRS,
        protocols=["http", "https", "mailto"],
        css_sanitizer=CSS_SANITIZER,
        strip=True,
    )


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.executescript(SCHEMA)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(posts)")}
    if "content_format" not in columns:
        try:
            conn.execute(
                "ALTER TABLE posts ADD COLUMN content_format TEXT NOT NULL DEFAULT 'text'"
            )
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
    if "section_id" not in columns:
        try:
            conn.execute(
                "ALTER TABLE posts ADD COLUMN section_id INTEGER "
                "REFERENCES sections(id) ON DELETE SET NULL"
            )
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
    if "is_shared" not in columns:
        try:
            conn.execute(
                "ALTER TABLE posts ADD COLUMN is_shared INTEGER NOT NULL DEFAULT 1"
            )
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
    if "status" not in columns:
        try:
            conn.execute(
                "ALTER TABLE posts ADD COLUMN status TEXT NOT NULL DEFAULT 'published'"
            )
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_posts_section ON posts(section_id)"
    )
    for name in ("技术", "话题"):
        conn.execute(
            "INSERT OR IGNORE INTO sections (name, created_at) VALUES (?, ?)",
            (name, now()),
        )
    try:
        conn.execute(
            """UPDATE posts
               SET section_id = (
                   SELECT s.id FROM sections s
                   JOIN categories c ON c.name = s.name
                   WHERE c.id = posts.category_id
               )
               WHERE section_id IS NULL AND category_id IS NOT NULL"""
        )
        conn.execute(
            "UPDATE posts SET category_id = NULL WHERE category_id IS NOT NULL"
        )
    except sqlite3.OperationalError:
        pass
    conn.execute(
        """INSERT OR IGNORE INTO post_history
           (post_id, user_id, username, action, detail, created_at)
           SELECT p.id, p.user_id, u.username, 'create', '', p.created_at
           FROM posts p JOIN users u ON u.id = p.user_id
           WHERE NOT EXISTS (
               SELECT 1 FROM post_history h
               WHERE h.post_id = p.id AND h.action = 'create'
           )"""
    )
    rows = conn.execute(
        "SELECT id, content FROM posts WHERE content_format = 'html' AND content LIKE '%<pre%'"
    ).fetchall()
    for post_id, content in rows:
        normalized = sanitize_post_html(content)
        if normalized != content:
            conn.execute(
                "UPDATE posts SET content = ? WHERE id = ?", (normalized, post_id)
            )
    conn.commit()
    conn.close()


def get_sections():
    return get_db().execute(
        "SELECT id, name, created_at FROM sections ORDER BY id"
    ).fetchall()


def section_options(selected_id=None):
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "selected": row["id"] == selected_id,
        }
        for row in get_sections()
    ]


def get_all_tags():
    db = get_db()
    section_ids = {row["name"]: row["id"] for row in get_sections()}
    rows = db.execute(
        """SELECT t.id, t.name, COUNT(DISTINCT pt.post_id) AS post_count,
                  COUNT(DISTINCT CASE WHEN p.section_id = ? THEN pt.post_id END)
                      AS tech_count,
                  COUNT(DISTINCT CASE WHEN p.section_id = ? THEN pt.post_id END)
                      AS topic_count
           FROM tags t
           JOIN post_tags pt ON pt.tag_id = t.id
           JOIN posts p ON p.id = pt.post_id
           WHERE p.status = 'published'
           GROUP BY t.id
           HAVING COUNT(DISTINCT pt.post_id) > 0
           ORDER BY post_count DESC, t.name COLLATE NOCASE""",
        (section_ids.get("技术"), section_ids.get("话题")),
    ).fetchall()

    tags = []
    for row in rows:
        if row["tech_count"] and row["topic_count"]:
            theme = "mixed"
        elif row["tech_count"]:
            theme = "tech"
        elif row["topic_count"]:
            theme = "topic"
        else:
            theme = ""
        tags.append(
            {
                "id": row["id"],
                "name": row["name"],
                "post_count": row["post_count"],
                "theme": theme,
            }
        )
    return tags


def get_post_tags(post_id):
    return get_db().execute(
        """SELECT t.id, t.name
           FROM tags t JOIN post_tags pt ON pt.tag_id = t.id
           WHERE pt.post_id = ?
           ORDER BY t.name COLLATE NOCASE""",
        (post_id,),
    ).fetchall()


def attach_post_tags(posts):
    posts = list(posts)
    if not posts:
        return []
    post_ids = [post["id"] for post in posts]
    placeholders = ",".join("?" for _ in post_ids)
    rows = get_db().execute(
        f"""SELECT pt.post_id, t.id, t.name
            FROM post_tags pt JOIN tags t ON t.id = pt.tag_id
            WHERE pt.post_id IN ({placeholders})
            ORDER BY t.name COLLATE NOCASE""",
        post_ids,
    ).fetchall()
    tag_map = {}
    for row in rows:
        tag_map.setdefault(row["post_id"], []).append(
            {"id": row["id"], "name": row["name"]}
        )
    result = []
    for post in posts:
        item = dict(post)
        item["tags"] = tag_map.get(post["id"], [])
        result.append(item)
    return result


def parse_tag_names(raw: str):
    names = []
    seen = set()
    for part in re.split(r"[,，;；\s]+", raw or ""):
        name = part.strip().lstrip("#").strip()
        if not name or len(name) > 20:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
        if len(names) >= 10:
            break
    return names


def set_post_tags(post_id: int, names) -> None:
    db = get_db()
    db.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
    for name in names:
        row = db.execute(
            "SELECT id FROM tags WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if row is None:
            try:
                cur = db.execute(
                    "INSERT INTO tags (name, created_at) VALUES (?, ?)",
                    (name, now()),
                )
                tag_id = cur.lastrowid
            except sqlite3.IntegrityError:
                tag_id = db.execute(
                    "SELECT id FROM tags WHERE name = ? COLLATE NOCASE", (name,)
                ).fetchone()["id"]
        else:
            tag_id = row["id"]
        db.execute(
            "INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?, ?)",
            (post_id, tag_id),
        )


def submitted_section_id():
    raw = (request.form.get("section_id") or "").strip()
    if not raw:
        return None
    try:
        section_id = int(raw)
    except ValueError:
        return None
    row = get_db().execute(
        "SELECT id FROM sections WHERE id = ?", (section_id,)
    ).fetchone()
    return row["id"] if row else None


def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def _safe_next(target: str) -> str:
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("index")


def render_content(text: str) -> Markup:
    escaped = html.escape(text)

    def _image(match: re.Match) -> str:
        alt, src = match.group(1), match.group(2)
        return (
            f'<img class="post-inline-image" src="{src}" alt="{alt}" loading="lazy">'
        )

    return Markup(IMAGE_MD_RE.sub(_image, escaped))


MARKDOWN_EXTENSIONS = ["fenced_code", "tables", "sane_lists", "nl2br"]


def render_markdown(text: str) -> Markup:
    rendered = markdown_lib.markdown(text, extensions=MARKDOWN_EXTENSIONS)
    return Markup(sanitize_post_html(rendered))


def prepare_submission():
    content_format = request.form.get("content_format") or "html"
    if content_format not in ("html", "markdown"):
        content_format = "html"
    raw = request.form.get("content") or ""
    if content_format == "markdown":
        stored = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
        rendered = render_markdown(stored)
    else:
        stored = sanitize_post_html(raw)
        rendered = Markup(stored)
    visible = bleach.clean(str(rendered), tags=[], strip=True).strip()
    return content_format, stored, rendered, visible


def excerpt_filter(text: str, content_format: str = "text", length: int = 160) -> str:
    if content_format == "html":
        cleaned = re.sub(r"<[^>]+>", " ", text)
        cleaned = html.unescape(cleaned)
    elif content_format == "markdown":
        rendered = str(render_markdown(text))
        cleaned = re.sub(r"<[^>]+>", " ", rendered)
        cleaned = html.unescape(cleaned)
    else:
        cleaned = IMAGE_MD_RE.sub(" [图片] ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > length:
        cleaned = cleaned[:length].rstrip() + "…"
    return cleaned


def editor_source(post) -> Markup:
    if post is None:
        return Markup("")
    if post["content_format"] == "html":
        return Markup(post["content"])
    if post["content_format"] == "markdown":
        return Markup("")
    return Markup(html.escape(post["content"]).replace("\n", "<br>"))


app.jinja_env.filters["excerpt"] = excerpt_filter

EXPORT_STYLE = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Noto Sans CJK SC", "Noto Sans CJK", "Microsoft YaHei", "SimSun", sans-serif;
  color: #1f2937;
  line-height: 1.85;
  font-size: 15px;
}
article { max-width: 100%; }
h1 { font-size: 24px; line-height: 1.35; margin: 0 0 10px; }
.meta {
  color: #6b7280;
  font-size: 13px;
  margin-bottom: 22px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e5e7eb;
}
.content p { margin: 0 0 1em; }
.content h1 { font-size: 22px; margin: 1.1em 0 0.5em; }
.content h2 { font-size: 20px; margin: 1.1em 0 0.5em; }
.content h3 { font-size: 18px; margin: 1em 0 0.4em; }
.content h4, .content h5, .content h6 { font-size: 16px; margin: 1em 0 0.4em; }
.content img { max-width: 100%; height: auto; margin: 12px 0; border-radius: 6px; }
.content blockquote {
  margin: 14px 0;
  padding: 6px 14px;
  border-left: 3px solid #4f46e5;
  background: #eef2ff;
  border-radius: 0 6px 6px 0;
}
.content ul, .content ol { margin: 0 0 1em; padding-left: 24px; }
.content li { margin: 3px 0; }
.content pre {
  background: #111827;
  color: #f9fafb;
  padding: 12px 14px;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 13px;
  font-family: "Consolas", "Courier New", "Noto Sans Mono CJK SC", monospace;
}
.content code {
  background: #f3f4f6;
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 0.92em;
  font-family: "Consolas", "Courier New", "Noto Sans Mono CJK SC", monospace;
}
.content pre code { background: none; padding: 0; color: inherit; }
.content a { color: #4f46e5; }
.content hr { border: none; border-top: 1px solid #e5e7eb; margin: 18px 0; }
.content table { width: 100%; border-collapse: collapse; margin: 0 0 1em; font-size: 13px; }
.content th, .content td { border: 1px solid #d1d5db; padding: 6px 9px; text-align: left; }
.content thead th { background: #f3f4f6; }
.footer {
  margin-top: 28px;
  padding-top: 10px;
  border-top: 1px solid #e5e7eb;
  color: #9ca3af;
  font-size: 12px;
}
"""

EXPORT_FORMATS = {"pdf", "doc", "html", "md", "txt"}


def _safe_filename(title: str) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", title).strip(" .")
    return (cleaned or "article")[:80]


def _attachment_header(filename: str) -> str:
    fallback = re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "download"
    quoted = urllib.parse.quote(filename)
    return f'attachment; filename="{fallback}"; filename*=UTF-8\'\'{quoted}'


def _download(data: bytes, content_type: str, filename: str) -> Response:
    response = Response(data, content_type=content_type)
    response.headers["Content-Disposition"] = _attachment_header(filename)
    return response


def _absolutize_images(text: str, host_url: str) -> str:
    base = host_url.rstrip("/")
    return re.sub(
        r'src="(/static/uploads/[^"]+)"',
        lambda match: f'src="{base}{match.group(1)}"',
        text,
    )


def _absolutize_markdown(text: str, host_url: str) -> str:
    base = host_url.rstrip("/")
    return re.sub(
        r"\]\((/static/uploads/[^)]+)\)",
        lambda match: f"]({base}{match.group(1)})",
        text,
    )


def _inline_images(text: str) -> str:
    def replace(match: re.Match) -> str:
        src = html.unescape(match.group(1))
        name = src.rsplit("/", 1)[-1]
        if not name or ".." in name:
            return match.group(0)
        try:
            resolved = (UPLOAD_DIR / name).resolve()
            resolved.relative_to(UPLOAD_DIR.resolve())
        except (ValueError, OSError):
            return match.group(0)
        if not resolved.is_file():
            return match.group(0)
        mime = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
        data = base64.b64encode(resolved.read_bytes()).decode("ascii")
        return f'src="data:{mime};base64,{data}"'

    return re.sub(r'src="(/static/uploads/[^"]+)"', replace, text)


def _html_to_markdown(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    for span in soup.find_all("span"):
        style = (span.get("style") or "").replace(" ", "").lower()
        if re.search(r"font-weight:(bold|[6-9]00)", style):
            span.name = "strong"
        elif "font-style:italic" in style:
            span.name = "em"
    text = markdownify(str(soup), heading_style="ATX", bullets="-")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _html_to_text(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    for img in soup.find_all("img"):
        img.replace_with("[图片]")
    for br in soup.find_all("br"):
        br.replace_with("\n")
    for tag in soup.find_all(
        ["p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "pre", "tr"]
    ):
        tag.append("\n")
    text = soup.get_text()
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def build_export_document(title: str, meta: str, content_html: str, note: str) -> str:
    safe_title = html.escape(title)
    safe_meta = html.escape(meta)
    safe_note = html.escape(note)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<style>{EXPORT_STYLE}</style>
</head>
<body>
<article>
<h1>{safe_title}</h1>
<div class="meta">{safe_meta}</div>
<div class="content">{content_html}</div>
<div class="footer">{safe_note}</div>
</article>
</body>
</html>
"""


def build_word_document(title: str, meta: str, content_html: str, note: str) -> str:
    safe_title = html.escape(title)
    safe_meta = html.escape(meta)
    safe_note = html.escape(note)
    return f"""<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word"
xmlns="http://www.w3.org/TR/REC-html40" lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View><w:Zoom>100</w:Zoom></w:WordDocument></xml><![endif]-->
<style>{EXPORT_STYLE}</style>
</head>
<body>
<article>
<h1>{safe_title}</h1>
<div class="meta">{safe_meta}</div>
<div class="content">{content_html}</div>
<div class="footer">{safe_note}</div>
</article>
</body>
</html>
"""


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("请先登录后再操作。", "warning")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("请先登录后再操作。", "warning")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def get_post_or_404(post_id: int):
    post = get_db().execute(
        """SELECT p.*, u.username, u.is_admin, sec.name AS section_name
           FROM posts p
           JOIN users u ON u.id = p.user_id
           LEFT JOIN sections sec ON sec.id = p.section_id
           WHERE p.id = ?""",
        (post_id,),
    ).fetchone()
    if post is None:
        abort(404)
    if post["status"] != "published" and (
        g.user is None or g.user["id"] != post["user_id"]
    ):
        abort(404)
    return post


def can_manage_post(post) -> bool:
    return g.user is not None and (
        g.user["id"] == post["user_id"] or bool(g.user["is_admin"])
    )


def can_edit_post(post) -> bool:
    return g.user is not None and (
        bool(post["is_shared"]) or g.user["id"] == post["user_id"]
    )


def can_manage_comment(comment) -> bool:
    return g.user is not None and (
        g.user["id"] == comment["user_id"] or bool(g.user["is_admin"])
    )


def record_history(post_id: int, action: str, detail: str = "", timestamp: str = "") -> None:
    db = get_db()
    db.execute(
        """INSERT INTO post_history
           (post_id, user_id, username, action, detail, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (post_id, g.user["id"], g.user["username"], action, detail, timestamp or now()),
    )


app.jinja_env.globals["can_manage_post"] = can_manage_post
app.jinja_env.globals["can_edit_post"] = can_edit_post


@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if g.user is None:
            session.clear()


@app.before_request
def csrf_protect():
    if request.method == "POST":
        expected = session.get("_csrf")
        provided = request.form.get("_csrf", "")
        if (
            not expected
            or not provided
            or not secrets.compare_digest(expected, provided)
        ):
            abort(400, description="表单校验失败，请刷新页面后重试。")


@app.context_processor
def inject_globals():
    return {"now_year": datetime.now().year}


@app.route("/")
def index():
    db = get_db()
    boards = []
    for row in get_sections():
        post_count = db.execute(
            "SELECT COUNT(*) FROM posts WHERE section_id = ? AND status = 'published'",
            (row["id"],),
        ).fetchone()[0]
        latest = db.execute(
            """SELECT id, title, created_at FROM posts
               WHERE section_id = ? AND status = 'published'
               ORDER BY created_at DESC, id DESC LIMIT 3""",
            (row["id"],),
        ).fetchall()
        theme = ""
        if row["name"] == "技术":
            theme = "tech"
        elif row["name"] == "话题":
            theme = "topic"
        boards.append(
            {
                "id": row["id"],
                "name": row["name"],
                "theme": theme,
                "post_count": post_count,
                "latest": latest,
            }
        )
    return render_template("home.html", boards=boards, tags=get_all_tags())


@app.route("/posts")
def posts_list():
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except (TypeError, ValueError):
        page = 1
    q = (request.args.get("q") or "").strip()
    per_page = app.config["PER_PAGE"]

    db = get_db()
    where = "WHERE p.status = 'published'"
    params = []
    if q:
        where += " AND (p.title LIKE ? OR p.content LIKE ?)"
        like = f"%{q}%"
        params = [like, like]

    total = db.execute(
        f"SELECT COUNT(*) FROM posts p {where}", params
    ).fetchone()[0]

    posts = db.execute(
        f"""SELECT p.*, u.username, u.is_admin, sec.name AS section_name,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
            FROM posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN sections sec ON sec.id = p.section_id
            {where}
            ORDER BY p.created_at DESC, p.id DESC
            LIMIT ? OFFSET ?""",
        params + [per_page, (page - 1) * per_page],
    ).fetchall()

    pages = max((total + per_page - 1) // per_page, 1)
    return render_template(
        "posts.html",
        posts=attach_post_tags(posts),
        page=page,
        pages=pages,
        q=q,
        total=total,
    )


@app.route("/drafts")
@login_required
def drafts_page():
    posts = get_db().execute(
        """SELECT * FROM posts
           WHERE user_id = ? AND status = 'draft'
           ORDER BY updated_at DESC, id DESC""",
        (g.user["id"],),
    ).fetchall()
    return render_template("drafts.html", posts=posts)


@app.route("/section/<int:section_id>")
def section_page(section_id):
    db = get_db()
    section = db.execute(
        "SELECT id, name FROM sections WHERE id = ?", (section_id,)
    ).fetchone()
    if section is None:
        abort(404)

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except (TypeError, ValueError):
        page = 1
    per_page = app.config["PER_PAGE"]
    total = db.execute(
        "SELECT COUNT(*) FROM posts WHERE section_id = ? AND status = 'published'",
        (section_id,),
    ).fetchone()[0]
    posts = db.execute(
        """SELECT p.*, u.username, u.is_admin, sec.name AS section_name,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
           FROM posts p
           JOIN users u ON u.id = p.user_id
           LEFT JOIN sections sec ON sec.id = p.section_id
           WHERE p.section_id = ? AND p.status = 'published'
           ORDER BY p.created_at DESC, p.id DESC
           LIMIT ? OFFSET ?""",
        (section_id, per_page, (page - 1) * per_page),
    ).fetchall()
    pages = max((total + per_page - 1) // per_page, 1)
    return render_template(
        "section.html",
        section=section,
        posts=attach_post_tags(posts),
        page=page,
        pages=pages,
        total=total,
    )


@app.route("/tags")
def tags_page():
    return render_template("tags.html", tags=get_all_tags())


@app.route("/tag/<int:tag_id>")
def tag_page(tag_id):
    db = get_db()
    tag = db.execute("SELECT id, name FROM tags WHERE id = ?", (tag_id,)).fetchone()
    if tag is None:
        abort(404)

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except (TypeError, ValueError):
        page = 1
    per_page = app.config["PER_PAGE"]
    total = db.execute(
        """SELECT COUNT(*) FROM post_tags pt
           JOIN posts p ON p.id = pt.post_id
           WHERE pt.tag_id = ? AND p.status = 'published'""",
        (tag_id,),
    ).fetchone()[0]
    posts = db.execute(
        """SELECT p.*, u.username, u.is_admin, sec.name AS section_name,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
           FROM posts p
           JOIN post_tags pt ON pt.post_id = p.id
           JOIN users u ON u.id = p.user_id
           LEFT JOIN sections sec ON sec.id = p.section_id
           WHERE pt.tag_id = ? AND p.status = 'published'
           ORDER BY p.created_at DESC, p.id DESC
           LIMIT ? OFFSET ?""",
        (tag_id, per_page, (page - 1) * per_page),
    ).fetchall()
    pages = max((total + per_page - 1) // per_page, 1)
    return render_template(
        "tag.html",
        tag=tag,
        posts=attach_post_tags(posts),
        page=page,
        pages=pages,
        total=total,
    )


@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = get_post_or_404(post_id)
    comments = get_db().execute(
        """SELECT c.*, u.username, u.is_admin
           FROM comments c JOIN users u ON u.id = c.user_id
           WHERE c.post_id = ?
           ORDER BY c.created_at ASC, c.id ASC""",
        (post_id,),
    ).fetchall()
    history = get_db().execute(
        """SELECT * FROM post_history
           WHERE post_id = ?
           ORDER BY created_at ASC, id ASC""",
        (post_id,),
    ).fetchall()
    last_update = next(
        (entry for entry in reversed(history) if entry["action"] == "update"), None
    )
    post_tags = get_post_tags(post_id)
    content_format = post["content_format"]
    if content_format == "html":
        content_html = Markup(post["content"])
        has_code = "<pre" in post["content"]
    elif content_format == "markdown":
        content_html = render_markdown(post["content"])
        has_code = "```" in post["content"] or "<pre" in post["content"]
    else:
        content_html = render_content(post["content"])
        has_code = False
    return render_template(
        "post.html",
        post=post,
        comments=comments,
        content_html=content_html,
        history=history,
        last_update=last_update,
        has_code=has_code,
        tags=post_tags,
    )


@app.route("/post/<int:post_id>/export/<fmt>")
def export_post(post_id, fmt):
    post = get_post_or_404(post_id)
    fmt = fmt.lower()
    if fmt not in EXPORT_FORMATS:
        abort(404)

    host_url = request.host_url
    content_format = post["content_format"]
    if content_format == "html":
        raw_html = post["content"]
    elif content_format == "markdown":
        raw_html = str(render_markdown(post["content"]))
    else:
        raw_html = str(render_content(post["content"]))
    title = post["title"]
    base_name = _safe_filename(title)

    meta = f"作者：{post['username']} · 创建于 {post['created_at'][:16]}"
    if post["section_name"]:
        meta += f" · 板块：{post['section_name']}"
    post_tags = get_post_tags(post_id)
    if post_tags:
        meta += " · 标签：" + "、".join(tag["name"] for tag in post_tags)
    last_update = get_db().execute(
        """SELECT username, created_at FROM post_history
           WHERE post_id = ? AND action = 'update'
           ORDER BY created_at DESC, id DESC LIMIT 1""",
        (post_id,),
    ).fetchone()
    if last_update:
        meta += (
            f" · 最后由 {last_update['username']} 修改于 "
            f"{last_update['created_at'][:16]}"
        )
    note = f"由 局域网博客 导出 · {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    if fmt == "md":
        if content_format == "html":
            body = _html_to_markdown(_absolutize_images(raw_html, host_url))
        else:
            body = _absolutize_markdown(post["content"], host_url)
        document = f"# {title}\n\n> {meta}\n\n{body}\n\n---\n\n{note}\n"
        return _download(
            document.encode("utf-8"),
            "text/markdown; charset=utf-8",
            f"{base_name}.md",
        )

    if fmt == "txt":
        if content_format in ("html", "markdown"):
            body = _html_to_text(raw_html)
        else:
            body = IMAGE_MD_RE.sub("[图片]", post["content"])
        underline = "=" * min(max(len(title), 4), 40)
        document = f"{title}\n{underline}\n\n{meta}\n\n{body}\n\n---\n{note}\n"
        return _download(
            document.encode("utf-8"),
            "text/plain; charset=utf-8",
            f"{base_name}.txt",
        )

    if fmt == "html":
        document = build_export_document(
            title, meta, _inline_images(raw_html), note
        )
        return _download(
            document.encode("utf-8"),
            "text/html; charset=utf-8",
            f"{base_name}.html",
        )

    if fmt == "doc":
        document = build_word_document(
            title, meta, _absolutize_images(raw_html, host_url), note
        )
        return _download(
            document.encode("utf-8"),
            "application/msword",
            f"{base_name}.doc",
        )

    content = _inline_images(raw_html)
    document = build_export_document(title, meta, content, note)
    try:
        result = subprocess.run(
            [sys.executable, str(BASE_DIR / "pdf_export.py"), str(BASE_DIR)],
            input=document.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(BASE_DIR),
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        app.logger.error("PDF export timed out for post %s", post_id)
        abort(500, description="PDF 生成超时，请稍后重试。")

    if result.returncode != 0:
        app.logger.error(
            "PDF export failed for post %s: %s",
            post_id,
            result.stderr.decode("utf-8", "replace")[:2000],
        )
        abort(500, description="PDF 生成失败，请稍后重试。")

    return _download(result.stdout, "application/pdf", f"{base_name}.pdf")


@app.route("/markdown/preview", methods=["POST"])
def markdown_preview():
    if g.user is None:
        return jsonify(error="请先登录。"), 401
    text = request.form.get("content") or ""
    if len(text) > 500_000:
        return jsonify(error="Markdown 内容过长。"), 400
    return jsonify(html=str(render_markdown(text)))


@app.route("/markdown/from-html", methods=["POST"])
def markdown_from_html():
    if g.user is None:
        return jsonify(error="请先登录。"), 401
    raw = request.form.get("html") or ""
    if len(raw) > 500_000:
        return jsonify(error="内容过长。"), 400
    return jsonify(markdown=_html_to_markdown(sanitize_post_html(raw)))


@app.route("/upload", methods=["POST"])
def upload_image():
    if g.user is None:
        return jsonify(error="请先登录后再上传图片。"), 401

    file = request.files.get("image")
    if file is None or not file.filename:
        return jsonify(error="请选择要上传的图片。"), 400

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTS:
        return jsonify(error="仅支持 JPG、PNG、GIF、WEBP 格式。"), 400

    data = file.read()
    if not data:
        return jsonify(error="图片内容为空。"), 400
    if len(data) > 8 * 1024 * 1024:
        return jsonify(error="图片不能超过 8MB。"), 400

    name = f"{secrets.token_hex(16)}{ext}"
    (UPLOAD_DIR / name).write_bytes(data)
    return jsonify(url=url_for("static", filename=f"uploads/{name}"))


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_post():
    form_title = ""
    editor_format = "html"
    editor_html = Markup("")
    markdown_source = ""
    section_id = None
    is_shared = 1
    tag_names = []
    tags_value = ""
    if request.method == "POST":
        action = request.form.get("action") or "publish"
        save_draft = action == "draft"
        form_title = (request.form.get("title") or "").strip()
        editor_format, stored, rendered, visible = prepare_submission()
        section_id = submitted_section_id()
        is_shared = 0 if request.form.get("is_shared") == "0" else 1
        tags_value = request.form.get("tags") or ""
        tag_names = parse_tag_names(tags_value)
        if editor_format == "markdown":
            markdown_source = stored
        else:
            editor_html = rendered

        error = None
        if not save_draft:
            if not form_title:
                error = "标题不能为空。"
            elif not visible and "<img" not in str(rendered):
                error = "正文不能为空。"
            elif len(form_title) > 120:
                error = "标题不能超过 120 个字符。"

        if error:
            flash(error, "error")
        else:
            db = get_db()
            timestamp = now()
            status_value = "draft" if save_draft else "published"
            cur = db.execute(
                """INSERT INTO posts
                   (user_id, title, content, content_format, section_id,
                    is_shared, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    g.user["id"],
                    form_title,
                    stored,
                    editor_format,
                    section_id,
                    is_shared,
                    status_value,
                    timestamp,
                    timestamp,
                ),
            )
            set_post_tags(cur.lastrowid, tag_names)
            if not save_draft:
                record_history(cur.lastrowid, "create", timestamp=timestamp)
            db.commit()
            if save_draft:
                flash("草稿已保存，仅自己可见。", "success")
                return redirect(url_for("edit_post", post_id=cur.lastrowid))
            flash("文章已发布。", "success")
            return redirect(url_for("post_detail", post_id=cur.lastrowid))
    return render_template(
        "post_edit.html",
        post=None,
        form_title=form_title,
        editor_html=editor_html,
        editor_format=editor_format,
        markdown_source=markdown_source,
        section_options=section_options(section_id),
        tags_value=tags_value,
        all_tags=get_all_tags(),
        is_shared=is_shared,
        can_change_permission=True,
    )


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = get_post_or_404(post_id)
    if not can_edit_post(post):
        abort(403)

    form_title = post["title"]
    section_id = post["section_id"]
    is_shared = post["is_shared"]
    can_change_permission = g.user["id"] == post["user_id"]
    old_tag_names = [tag["name"] for tag in get_post_tags(post_id)]
    tags_value = "，".join(old_tag_names)
    editor_format = "markdown" if post["content_format"] == "markdown" else "html"
    editor_html = Markup("") if editor_format == "markdown" else editor_source(post)
    markdown_source = post["content"] if editor_format == "markdown" else ""
    tag_names = old_tag_names
    post_is_draft = post["status"] == "draft"
    if request.method == "POST":
        action = request.form.get("action") or "publish"
        save_draft = action == "draft" and post_is_draft
        form_title = (request.form.get("title") or "").strip()
        editor_format, stored, rendered, visible = prepare_submission()
        section_id = submitted_section_id()
        requested_shared = 0 if request.form.get("is_shared") == "0" else 1
        is_shared = requested_shared if can_change_permission else post["is_shared"]
        tags_value = request.form.get("tags") or ""
        tag_names = parse_tag_names(tags_value)
        if editor_format == "markdown":
            markdown_source = stored
            editor_html = Markup("")
        else:
            markdown_source = ""
            editor_html = rendered

        error = None
        if not save_draft:
            if not form_title:
                error = "标题不能为空。"
            elif not visible and "<img" not in str(rendered):
                error = "正文不能为空。"
            elif len(form_title) > 120:
                error = "标题不能超过 120 个字符。"

        if error:
            flash(error, "error")
        elif save_draft:
            db = get_db()
            timestamp = now()
            db.execute(
                """UPDATE posts
                   SET title = ?, content = ?, content_format = ?, section_id = ?,
                       is_shared = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    form_title,
                    stored,
                    editor_format,
                    section_id,
                    is_shared,
                    timestamp,
                    post_id,
                ),
            )
            set_post_tags(post_id, tag_names)
            db.commit()
            flash("草稿已保存，仅自己可见。", "success")
            return redirect(url_for("edit_post", post_id=post_id))
        else:
            db = get_db()
            timestamp = now()
            if post_is_draft:
                db.execute(
                    """UPDATE posts
                       SET title = ?, content = ?, content_format = ?, section_id = ?,
                           is_shared = ?, status = 'published', updated_at = ?
                       WHERE id = ?""",
                    (
                        form_title,
                        stored,
                        editor_format,
                        section_id,
                        is_shared,
                        timestamp,
                        post_id,
                    ),
                )
                set_post_tags(post_id, tag_names)
                existing = db.execute(
                    "SELECT 1 FROM post_history WHERE post_id = ? AND action = 'create'",
                    (post_id,),
                ).fetchone()
                if existing is None:
                    record_history(post_id, "create", timestamp=timestamp)
                db.commit()
                flash("草稿已发布。", "success")
                return redirect(url_for("post_detail", post_id=post_id))

            changed = []
            if form_title != post["title"]:
                changed.append("标题")
            if stored != post["content"] or editor_format != post["content_format"]:
                changed.append("正文")
            if section_id != post["section_id"]:
                changed.append("板块")
            if sorted(tag_names) != sorted(old_tag_names):
                changed.append("标签")
            if is_shared != post["is_shared"]:
                changed.append("权限")
            if not changed:
                flash("没有检测到修改。", "warning")
                return redirect(url_for("post_detail", post_id=post_id))

            db.execute(
                """UPDATE posts
                   SET title = ?, content = ?, content_format = ?, section_id = ?,
                       is_shared = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    form_title,
                    stored,
                    editor_format,
                    section_id,
                    is_shared,
                    timestamp,
                    post_id,
                ),
            )
            set_post_tags(post_id, tag_names)
            record_history(
                post_id,
                "update",
                detail="修改了" + "和".join(changed),
                timestamp=timestamp,
            )
            db.commit()
            flash("文章已更新。", "success")
            return redirect(url_for("post_detail", post_id=post_id))

    return render_template(
        "post_edit.html",
        post=post,
        form_title=form_title,
        editor_html=editor_html,
        editor_format=editor_format,
        markdown_source=markdown_source,
        section_options=section_options(section_id),
        tags_value=tags_value,
        all_tags=get_all_tags(),
        is_shared=is_shared,
        can_change_permission=can_change_permission,
    )


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = get_post_or_404(post_id)
    if not can_manage_post(post):
        abort(403)
    db = get_db()
    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash("文章已删除。", "success")
    return redirect(url_for("index"))


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    post = get_post_or_404(post_id)
    if post["status"] != "published":
        abort(404)
    content = (request.form.get("content") or "").strip()
    if not content:
        flash("评论内容不能为空。", "error")
    elif len(content) > 2000:
        flash("评论不能超过 2000 个字符。", "error")
    else:
        db = get_db()
        db.execute(
            """INSERT INTO comments (post_id, user_id, content, created_at)
               VALUES (?, ?, ?, ?)""",
            (post_id, g.user["id"], content, now()),
        )
        db.commit()
        flash("评论已发布。", "success")
    return redirect(url_for("post_detail", post_id=post_id) + "#comments")


@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    db = get_db()
    comment = db.execute(
        "SELECT * FROM comments WHERE id = ?", (comment_id,)
    ).fetchone()
    if comment is None:
        abort(404)
    if not can_manage_comment(comment):
        abort(403)
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    flash("评论已删除。", "success")
    return redirect(url_for("post_detail", post_id=comment["post_id"]) + "#comments")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        error = None

        if not USERNAME_RE.match(username):
            error = "用户名不能包含空格、斜杠，长度为 1-20 个字符。"
        elif len(password) < 6:
            error = "密码至少需要 6 位。"
        elif password != confirm:
            error = "两次输入的密码不一致。"

        if error is None:
            db = get_db()
            user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            is_admin = 1 if (
                user_count == 0 or username == app.config["ADMIN_USERNAME"]
            ) else 0
            try:
                cur = db.execute(
                    """INSERT INTO users (username, password_hash, is_admin, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (username, generate_password_hash(password), is_admin, now()),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "该用户名已被注册。"
            else:
                session.clear()
                session["user_id"] = cur.lastrowid
                flash("注册成功，开始写点什么吧！", "success")
                return redirect(url_for("index"))

        flash(error, "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("index"))

    next_url = request.args.get("next") or request.form.get("next") or ""

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("用户名或密码错误。", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash(f"欢迎回来，{user['username']}！", "success")
            return redirect(_safe_next(next_url))

    return render_template("login.html", next_url=next_url)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("已退出登录。", "success")
    return redirect(url_for("index"))


@app.route("/user/<username>")
def user_page(username):
    db = get_db()
    profile = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if profile is None:
        abort(404)
    posts = db.execute(
        """SELECT p.*, u.username, u.is_admin, sec.name AS section_name,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
           FROM posts p
           JOIN users u ON u.id = p.user_id
           LEFT JOIN sections sec ON sec.id = p.section_id
           WHERE p.user_id = ? AND p.status = 'published'
           ORDER BY p.created_at DESC, p.id DESC""",
        (profile["id"],),
    ).fetchall()
    return render_template("user.html", profile=profile, posts=attach_post_tags(posts))


@app.route("/healthz")
def healthz():
    return "ok"


@app.errorhandler(413)
def too_large(_e):
    if request.path == "/upload":
        return jsonify(error="图片不能超过 8MB。"), 413
    return (
        render_template("error.html", code=413, message="上传内容过大。"),
        413,
    )


@app.errorhandler(400)
def bad_request(e):
    return (
        render_template(
            "error.html", code=400, message=getattr(e, "description", "请求有误")
        ),
        400,
    )


@app.errorhandler(403)
def forbidden(_e):
    return (
        render_template("error.html", code=403, message="你没有权限执行该操作。"),
        403,
    )


@app.errorhandler(404)
def not_found(_e):
    return (
        render_template("error.html", code=404, message="页面不存在或已被删除。"),
        404,
    )


init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
