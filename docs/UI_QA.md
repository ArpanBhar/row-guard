# Dashboard visual QA

Updated 4 November 2026. The [original concept](dashboard-concept.png) guided the screen hierarchy. The shipped dashboard was inspected in headless Chrome through the DevTools Protocol at 1440 × 900 desktop and 390 × 844 mobile sizes. The live daemon reported `MONITORING`, a trained model score, five current feature readings, and `LOCAL ONLY` integrity status. These values came from the local PMU/API, not a mock.

| Check | Result |
| --- | --- |
| Overview | Four summary cards keep PMU state, score, active incidents, and evidence status visible. Redundant system-health card and chart legend were removed; detailed health remains in its own view. |
| Feature chart | Real scores and feature readings render in the desktop layout. Mobile time ticks were reduced to avoid label overlap. |
| Responsive layout | Five navigation items remain visible at 390 pixels; dashboard cards stack; document width and viewport width were both 390 pixels. |
| Tunnel fallback | With `/api/v1/events` blocked in Chrome, the page still showed `MONITORING`, remained connected, and updated its score through two-second polling. This simulates a Quick Tunnel where SSE is unavailable; no live Cloudflare Tunnel was used in this test. |
| Asset/API origin | HTML, CSS, JavaScript, and `/api/v1` are served by the same FastAPI app. The page's Content Security Policy limits scripts and connections to that origin. API JSON has `Cache-Control: no-store`; no cross-origin access header is enabled. |

The dashboard deliberately says `LOCAL ONLY` when there is no independent checkpoint receiver. A score or candidate process name is not presented as proof of a physical bit flip or of process causation. The visible-history reset remains on the Incidents view and preserves signed audit records.
