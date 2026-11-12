"""
Document Traffic Monitor — 수집 서버 + 관리자 대시보드
- GET /t/{token}  : 추적 엔드포인트. 접근 시 이벤트 기록 후 미끼 페이지(검정 배경+이미지) 반환.
- GET /admin      : 관리자 대시보드(로그인 필요). PDF 추적 이벤트만 집계.
- 30일(기본) 경과 토큰은 기록을 멈추고 미끼 페이지만 반환.
관리자 활동과 PDF 추적 이벤트는 테이블/집계를 분리한다.
"""
import os, hashlib, datetime as dt, json
from pathlib import Path
from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature
from sqlalchemy import (create_engine, Column, Integer, String, DateTime, Boolean,
                        text, func)
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------- 설정
BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
TRACK_DAYS   = int(os.getenv("TRACK_DAYS", "30"))          # 추적 유효기간(일)
ISSUE_DATE   = os.getenv("ISSUE_DATE", "")                  # 비우면 서버 최초 기동일 기준
ADMIN_USER   = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-please")
SECRET_KEY   = os.getenv("SECRET_KEY", "dev-secret-change-me")
TRUST_PROXY  = os.getenv("TRUST_PROXY", "true").lower() == "true"   # PaaS 뒤에 있으면 true
DEDUP_SEC    = int(os.getenv("DEDUP_WINDOW_SEC", "15"))
PUBLIC_DASHBOARD = os.getenv("PUBLIC_DASHBOARD", "true").lower() == "true"  # true면 /admin 로그인 없이 공개
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE/'data'/'events.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

# 4개 PDF ↔ 토큰 ↔ 표시명  (표시명은 관리자 화면에 노출; 자유롭게 수정)
DOCS = {
    "18c9cd3f6dbfc98e": {"label": "A", "name": os.getenv("DOC_A_NAME", "기획서 A (13p)")},
    "efe7e9b636a1c8e4": {"label": "B", "name": os.getenv("DOC_B_NAME", "API 연동 기획서 (35p)")},
    "b3561b40ba4ae7be": {"label": "C", "name": os.getenv("DOC_C_NAME", "기획서 C (21p)")},
    "35451019e06bd0d2": {"label": "D", "name": os.getenv("DOC_D_NAME", "드랍쉬핑 서비스기획서 통합본 (203p)")},
}

# ---------------------------------------------------------------- DB
Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Event(Base):                       # PDF 추적 이벤트 (집계 대상)
    __tablename__ = "document_access_event"
    id = Column(Integer, primary_key=True)
    token = Column(String(64), index=True)
    doc_label = Column(String(8), index=True)
    received_at = Column(DateTime, index=True)      # UTC 저장
    observed_ip = Column(String(64))
    user_agent = Column(String(512))
    source_class = Column(String(32))
    is_dup = Column(Boolean, default=False)

class AdminAudit(Base):                   # 관리자 활동 (집계 제외)
    __tablename__ = "admin_audit_log"
    id = Column(Integer, primary_key=True)
    at = Column(DateTime)
    action = Column(String(32))
    ip = Column(String(64))
    detail = Column(String(256))

if DATABASE_URL.startswith("sqlite"):
    (BASE / "data").mkdir(exist_ok=True)
Base.metadata.create_all(engine)

# ---------------------------------------------------------------- 유틸
signer = URLSafeTimedSerializer(SECRET_KEY, salt="dtm-admin")
ADJ = ["멍청한","귀여운","졸린","배고픈","수줍은","용감한","느긋한","엉뚱한","통통한","새침한","씩씩한","나른한"]
ANI = ["사자","호랑이","너구리","펭귄","수달","다람쥐","고슴도치","판다","코알라","햄스터","부엉이","여우"]

AI_UA   = ["gptbot","chatgpt-user","oai-searchbot","claudebot","claude-web","anthropic",
           "google-extended","gemini","perplexitybot","perplexity","bytespider","amazonbot",
           "ccbot","cohere","applebot-extended","meta-externalagent","diffbot","youbot"]
PREVIEW_UA = ["facebookexternalhit","twitterbot","slackbot","discordbot","whatsapp",
              "telegrambot","linkedinbot","embedly","skypeuripreview","redditbot"]
CRAWLER_UA = ["bot","crawler","spider","scan","preview","fetch"]

def classify(ua: str) -> str:
    u = (ua or "").lower()
    if any(k in u for k in AI_UA): return "AI (추정)"
    if any(k in u for k in PREVIEW_UA): return "링크 프리뷰"
    if any(k in u for k in CRAWLER_UA): return "자동요청 (추정)"
    return "미확인"

def visitor_label(ip: str, ua: str) -> str:
    h = int(hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest(), 16)
    return f"{ADJ[h % len(ADJ)]} {ANI[(h//7) % len(ANI)]}-{100 + (h % 900)}"

def client_ip(req: Request) -> str:
    if TRUST_PROXY:
        xff = req.headers.get("x-forwarded-for")
        if xff: return xff.split(",")[0].strip()   # 신뢰 프록시 환경에서만 첫 홉 사용
    return req.client.host if req.client else "-"

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4: return f"{parts[0]}.{parts[1]}.xxx.xxx"
    return ip[:6] + "…" if len(ip) > 6 else ip

def issue_date() -> dt.datetime:
    if ISSUE_DATE:
        try: return dt.datetime.fromisoformat(ISSUE_DATE)
        except Exception: pass
    # 비어 있으면 서버가 기억하는 최초 기동일(파일 마커)
    marker = BASE / "data" / "issued_at.txt"
    try:
        if marker.exists(): return dt.datetime.fromisoformat(marker.read_text().strip())
        marker.parent.mkdir(exist_ok=True)
        now = dt.datetime.utcnow(); marker.write_text(now.isoformat()); return now
    except Exception:
        return dt.datetime.utcnow()

def expires_at() -> dt.datetime:
    return issue_date() + dt.timedelta(days=TRACK_DAYS)

def is_expired() -> bool:
    return dt.datetime.utcnow() > expires_at()

# ---------------------------------------------------------------- 앱
app = FastAPI(title="Document Traffic Monitor", docs_url=None, redoc_url=None, openapi_url=None)

DECOY_HTML = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Document</title>
<style>html,body{height:100%}body{margin:0;background:#000;display:flex;align-items:center;justify-content:center;min-height:100vh}img{height:396px;width:auto;display:block}</style>
</head><body><img src="/static/decoy.webp" alt=""></body></html>"""

@app.get("/t/{token}", response_class=HTMLResponse)
def track(token: str, request: Request):
    """추적 엔드포인트: 유효 토큰이면 이벤트 기록, 어떤 경우든 미끼 페이지만 반환(관리자 정보 미노출)."""
    doc = DOCS.get(token)
    if doc and not is_expired():
        ip = client_ip(request); ua = request.headers.get("user-agent", "")
        db = SessionLocal()
        try:
            since = dt.datetime.utcnow() - dt.timedelta(seconds=DEDUP_SEC)
            dup = db.query(Event).filter(Event.token == token, Event.observed_ip == ip,
                                         Event.user_agent == ua, Event.received_at >= since).first() is not None
            db.add(Event(token=token, doc_label=doc["label"], received_at=dt.datetime.utcnow(),
                         observed_ip=ip, user_agent=ua[:512], source_class=classify(ua), is_dup=dup))
            db.commit()
        finally:
            db.close()
    # 응답은 이벤트 기록에 필요한 최소한 — 통계/관리자 정보 없음
    return HTMLResponse(DECOY_HTML, headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"})

@app.get("/static/decoy.webp")
def decoy_img():
    return FileResponse(STATIC / "decoy.webp", media_type="image/webp")

# ---------------- 관리자 인증
def current_admin(request: Request):
    tok = request.cookies.get("dtm_session")
    if not tok: return None
    try:
        data = signer.loads(tok, max_age=60 * 60 * 12)
        return data.get("u")
    except BadSignature:
        return None

def require_admin(request: Request):
    if PUBLIC_DASHBOARD: return "public"
    u = current_admin(request)
    if not u: raise HTTPException(status_code=307, headers={"Location": "/admin/login"})
    return u

LOGIN_HTML = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>DTM · 로그인</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0d0c;color:#f0efec;font-family:system-ui,-apple-system,"Apple SD Gothic Neo",sans-serif}
.card{background:#1a1a19;border:1px solid #2c2c2a;border-radius:14px;padding:28px 26px;width:300px}
h1{font-size:15px;margin:0 0 4px}p{font-size:12px;color:#8f8e86;margin:0 0 18px}
label{font-size:12px;color:#bdbcb3;display:block;margin:12px 0 5px}
input{width:100%;box-sizing:border-box;height:38px;border:1px solid #3a3a37;background:#222220;color:#f0efec;border-radius:9px;padding:0 11px;font-size:14px}
button{margin-top:18px;width:100%;height:40px;border:0;border-radius:9px;background:#3987e5;color:#fff;font-weight:600;font-size:14px;cursor:pointer}
.err{color:#e66767;font-size:12px;margin-top:12px;__ERRDISP__}</style></head><body>
<form class="card" method="post" action="/admin/login">
<h1>Document Traffic Monitor</h1><p>관리자 로그인</p>
<label>아이디</label><input name="username" autocomplete="username" autofocus>
<label>비밀번호</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">로그인</button><div class="err">아이디 또는 비밀번호가 올바르지 않습니다.</div>
</form></body></html>"""

@app.get("/admin/login", response_class=HTMLResponse)
def login_form(request: Request, bad: int = 0):
    html = LOGIN_HTML.replace("__ERRDISP__", "" if bad else "display:none")
    return HTMLResponse(html)

@app.post("/admin/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = client_ip(request)
    db = SessionLocal()
    try:
        ok = (username == ADMIN_USER and password == ADMIN_PASSWORD)
        db.add(AdminAudit(at=dt.datetime.utcnow(), action="login_ok" if ok else "login_fail",
                          ip=ip, detail=username[:64]))
        db.commit()
    finally:
        db.close()
    if not ok:
        return RedirectResponse("/admin/login?bad=1", status_code=303)
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie("dtm_session", signer.dumps({"u": username}),
                    httponly=True, samesite="lax", max_age=60*60*12,
                    secure=not DATABASE_URL.startswith("sqlite"))
    return resp

@app.get("/admin/logout")
def logout():
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("dtm_session"); return resp

# ---------------- 관리자 API (document_access_event만 집계)
@app.get("/admin/api/stats")
def api_stats(request: Request, _: str = Depends(require_admin)):
    db = SessionLocal()
    try:
        total = db.query(func.count(Event.id)).scalar() or 0
        rows = db.query(Event.doc_label, func.count(Event.id)).group_by(Event.doc_label).all()
        per_doc = {l: c for l, c in rows}
        # 일자별(최근 14일) 문서별 집계 — KST 기준 날짜
        evs = db.query(Event.doc_label, Event.received_at).all()
        days = [(dt.datetime.utcnow() + dt.timedelta(hours=9)).date() - dt.timedelta(days=i) for i in range(13, -1, -1)]
        day_keys = [d.isoformat() for d in days]
        series = {d["label"]: {k: 0 for k in day_keys} for d in DOCS.values()}
        today_kst = (dt.datetime.utcnow() + dt.timedelta(hours=9)).date().isoformat()
        today_cnt = 0
        for lbl, ts in evs:
            k = (ts + dt.timedelta(hours=9)).date().isoformat()
            if lbl in series and k in series[lbl]:
                series[lbl][k] += 1
            if k == today_kst: today_cnt += 1
        last = db.query(func.max(Event.received_at)).scalar()
        last_kst = (last + dt.timedelta(hours=9)).strftime("%Y-%m-%d %H:%M") if last else "—"
        docs_meta = [{"label": d["label"], "name": d["name"], "count": per_doc.get(d["label"], 0)}
                     for d in DOCS.values()]
        return {"total": total, "today": today_cnt, "last": last_kst,
                "tracked": len(DOCS), "day_keys": day_keys,
                "series": {l: [series[l][k] for k in day_keys] for l in series},
                "docs": docs_meta,
                "expires_kst": (expires_at() + dt.timedelta(hours=9)).strftime("%Y-%m-%d"),
                "expired": is_expired()}
    finally:
        db.close()

@app.get("/admin/api/events")
def api_events(request: Request, page: int = 1, size: int = 20, _: str = Depends(require_admin)):
    size = 50 if size not in (20, 50) else size
    page = max(1, page)
    db = SessionLocal()
    try:
        total = db.query(func.count(Event.id)).scalar() or 0
        q = (db.query(Event).order_by(Event.received_at.desc())
             .offset((page-1)*size).limit(size).all())
        name_by = {d["label"]: d["name"] for d in DOCS.values()}
        items = [{
            "eid": f"EV-{e.id}",
            "doc_label": e.doc_label,
            "doc_name": name_by.get(e.doc_label, e.doc_label),
            "label": visitor_label(e.observed_ip, e.user_agent),
            "time": (e.received_at + dt.timedelta(hours=9)).strftime("%Y-%m-%d %H:%M:%S"),
            "ip": mask_ip(e.observed_ip or "-"),
            "ua": e.user_agent or "",
            "source": e.source_class,
            "status": "중복" if e.is_dup else "기록됨",
        } for e in q]
        return {"total": total, "page": page, "size": size, "items": items}
    finally:
        db.close()

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if not PUBLIC_DASHBOARD and not current_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    return HTMLResponse((BASE / "templates" / "dashboard.html").read_text(encoding="utf-8"))

@app.get("/")
def root():
    return JSONResponse({"service": "Document Traffic Monitor", "ok": True})

@app.get("/healthz")
def healthz():
    return {"ok": True}
