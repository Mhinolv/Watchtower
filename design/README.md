# Watchtower design files

Issue #31 owns this folder. Engineers apply the design in their own issues.
Open a mockup HTML file in a browser. Add `?theme=dark` for dark mode. Add the state shown in the table, for example `?state=stale`.
Run `design/render-all.sh` to make every PNG file. Run `design/render.sh <name>` for one mockup.
All names of apps, packages, findings and incidents in the mockups are sample data.

## Logo (`design/logo/`)
| File | Use | Issue |
|---|---|---|
| `watchtower-icon.svg` | Source of the app icon | #31 |
| `watchtower-icon-1024.png` | 1024 px render of the icon | #31 |
| `AppIcon.icns` | App bundle icon, made with `iconutil` | #31, #4 |
| `menubar-template.svg`, `.png`, `@2x.png` | Menu bar icon, 18 pt template image | #5 |
| `menubar-alert-template.svg`, `.png`, `@2x.png` | Menu bar icon while findings are open | #5, #8 |

## System
| File | Use | Issue |
|---|---|---|
| `system.md` | Colors, type, spacing, badges, symbols | #5, #6, #8 to #12 |

## Mockups (`design/mockups/`)
Each screen has one HTML file. Each PNG has a `-light` and a `-dark` version.

| HTML file | Screen and states (query) | Issue |
|---|---|---|
| `dashboard.html` | Main window, Apps. `state=` `stale`, `partial`, `running`, `failed`, `never` | #5, #3, #4 |
| `findings.html` | List and evidence detail. `view=` `partial`, `deferred`, `resolved`, `empty` | #8, #9, #17 |
| `update-dialog.html` | Plan, major version alert, running, three results | #6 |
| `update-dialog-npm-uv.html` | npm and uv plan rows, scripts and build step, results, not supported | #10, #11 |
| `update-log.html` | Update Log. `view=` `notverified`, `failed` | #6 |
| `settings.html` | Settings. `tab=` `general`, `projects`, `services` | #2, #5, #12, #17 |
| `backlog.html` | Backlog. `view=empty` | #5, #8 |
| `incidents.html` | Incidents and Check Sources. `view=` `missed`, `failed`, `checking`, `empty` | #12 |
| `menubar.html` | Menu style, popover, all clear, stale | #5 |
| `shared.css`, `shared.js`, `dialog.css` | Tokens and helpers | #31 |

Mockup symbols are drawings. The SF Symbol name in each `data-i` attribute or in `system.md` is the spec.
