# Document Traffic Monitor

내부 기밀 PDF에 심은 추적 URL이 AI 서비스 등에서 **실제로 호출**되는지 관측하는 수집 서버 + 공개 대시보드.

- `GET /t/{token}` — 추적 엔드포인트. 접근 시 이벤트 기록 후 **미끼 페이지(검정 배경 + 이미지)** 반환.
- `GET /admin` — 대시보드(기본 **로그인 없이 공개**). PDF 추적 이벤트만 집계.
- 토큰은 발급 후 **30일**간만 기록(이후 자동 중지). 관리자 활동과 추적 이벤트는 테이블/집계 분리.

## 토큰 ↔ PDF
| PDF | token | 추적 URL |
|---|---|---|
| A | `18c9cd3f6dbfc98e` | `https://<배포주소>/t/18c9cd3f6dbfc98e` |
| B | `efe7e9b636a1c8e4` | `https://<배포주소>/t/efe7e9b636a1c8e4` |
| C | `b3561b40ba4ae7be` | `https://<배포주소>/t/b3561b40ba4ae7be` |
| D | `35451019e06bd0d2` | `https://<배포주소>/t/35451019e06bd0d2` |

## 로컬 실행
```bash
pip install -r requirements.txt
cp .env.example .env            # 값 수정
uvicorn app.main:app --reload   # http://127.0.0.1:8000/admin
```

## 배포 (Render.com 무료, 카드 불필요)
1. 이 폴더를 GitHub 저장소로 올린다.
2. Render → **New > Blueprint** → 저장소 선택 → `render.yaml` 자동 인식.
3. 배포되면 `https://document-traffic-monitor-xxxx.onrender.com` 주소가 생긴다.
   - 추적 URL = 그 주소 + `/t/<token>`
   - 대시보드 = 그 주소 + `/admin`
4. 위 추적 URL을 PDF에 심는다(embed 스크립트는 별도 제공).

## 주요 환경변수
| 변수 | 기본 | 설명 |
|---|---|---|
| `TRACK_DAYS` | 30 | 추적 유효기간(일) |
| `PUBLIC_DASHBOARD` | true | true면 `/admin` 로그인 없이 공개 |
| `TRUST_PROXY` | true | PaaS 프록시 뒤 X-Forwarded-For 첫 홉 사용 |
| `DATABASE_URL` | (SQLite) | 설정 시 PostgreSQL 사용. 무료 호스팅은 Postgres 권장(재배포 시 데이터 보존) |
| `SECRET_KEY` | — | 세션 서명 키(로그인 모드일 때) |
| `DOC_A_NAME`~`DOC_D_NAME` | — | 대시보드 표시명 |

## 참고 / 한계
- 추적 기록 = "URL에 접근 요청이 있었다"는 사실. **업로드·유출을 100% 증명하지 않음.**
- Observed IP는 네트워크 IP(주로 AI/프록시)로 개인 신원이 아님. 대시보드에선 마스킹.
- AI가 URL을 **호출해야** 기록됨. 호출 기록=강한 유출 신호, 무기록=판정 불가(카나리 토큰 특성).
