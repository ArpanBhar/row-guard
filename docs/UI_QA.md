# Dashboard visual QA

The [concept](dashboard-concept.png) was generated for the complete primary dashboard screen. The implementation was checked using headless Chrome DevTools Protocol because the Browser plugin and Playwright are unavailable in this environment. The reference was inspected at its native 1487×1059 size; the implementation was rendered at 1487×1059 and at an emulated 390×844 mobile viewport. The final screenshots were inspected with `view_image` alongside the concept. Chrome also clicked Features and Evidence, and the feature list contained all nine registry entries.

| Comparison point | Result |
| --- | --- |
| Sidebar and navigation | Brand mark, five views, and active state follow the concept. Mobile uses five evenly spaced items; all are visible at 390 pixels. |
| Header and status | Main title and host sit at left; the live PMU state sits at right. Error text wraps on mobile. The real host name and permission error replace the concept's invented values. |
| Summary strip | Five status columns match the concept's hierarchy. Integrity reads `LOCAL ONLY` because no independent receiver is configured, replacing the concept's unsupported green `OK` claim. |
| Risk graph and feature readings | Large chart and right-hand values table retain the same two-column desktop anatomy. Missing PMU data is shown as unavailable, with actual PMU feature names replacing the concept's unrelated placeholder labels. |
| Incident and integrity region | Lower two-column layout matches the reference. Empty incidents, signed sequence, and off-host status use real API data. |
| Typography, palette, spacing | Deep navy headings, white ground, teal navigation, amber degraded state, thin separators, and open sections match the reference. Chart height was adjusted to align the lower region's vertical position. |
| Responsive behavior | Mobile stacks the dashboard content, keeps navigation visible, wraps the PMU error, and has no horizontal document overflow (`clientWidth=390`, `scrollWidth=390`). |

Above-the-fold copy differences are intentional: the reference invented a host ID, showed a misleading `OK` integrity state, and contained unrelated electrical-engineering features. The implementation uses the live host identity, `LOCAL ONLY`, and RowGuard's PMU feature registry. No unrelated navigation or attack controls were added.

No material visual mismatch remains in the primary overview for this prototype. Further browser work should cover long live histories and incidents once real PMU data is available. The core interaction path checked was Overview → Features → Evidence; the service returned live status, features, incidents, integrity, event stream, and timeseries requests.
