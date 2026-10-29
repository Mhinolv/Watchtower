# Watchtower design system

Use system controls, fonts and SF Symbols. Support light and dark mode. Pair each color with a symbol and a word.

## Color
Set `AccentColor` in the asset catalog. Use semantic system colors for surfaces and text.

| Role | Light | Dark |
|---|---|---|
| Accent (Watchtower Indigo) | `#5B4FD9` | `#8E86FF` |
| Beacon (icon only) | `#FFC247` | `#FFC247` |
| Green, `Up to date` | text `#1F7A3A` | `#5FDC7D` |
| Blue, `Update available` | text `#0B5FD6` | `#6CB0FF` |
| Red, `Vulnerable`, `Open` | text `#C4271D` | `#FF7A70` |
| Orange, `Error`, stale, partial | text `#9A5200` | `#FFB340` |
| Gray, `Unknown`, `Pinned`, `Manual update` | text `#5C5C63` | `#A8A8AE` |

Badge background: the symbol color at 12 to 20 percent opacity. Contrast is 4.5 or more.

## StatusBadge
Capsule, 21 pt high, 11.5 pt semibold, symbol and word. Names and symbols follow #5.

| Badge | Symbol |
|---|---|
| `Up to date` | `checkmark.circle` |
| `Update available` | `arrow.up.circle` |
| `Vulnerable` | `exclamationmark.shield` |
| `Unknown` | `questionmark.circle` |
| `Error` | `exclamationmark.triangle` |
| `Pinned` | `pin` |
| `Manual update` | `hand.raised` |
| `Known exploited` (#9), solid red | `flame.fill` |
| `Malware` (#9), solid red | `exclamationmark.octagon.fill` |

Result symbols (#6): `checkmark.seal` green, `exclamationmark.triangle` orange, `xmark.octagon` red.

## Type
Use the system font. Use `.monospaced` for commands, versions in logs, and IDs like `SEC-0001`.

| Use | Size | Weight |
|---|---|---|
| Window title, sheet title | 15 to 17 pt | Bold |
| Detail title | 20 pt | Bold |
| Body, table | 13 pt | Regular |
| Label, badge | 11.5 to 12.5 pt | Medium or semibold |
| Section header | 11 pt | Semibold, secondary color |

## Spacing and shape
- Grid: 4 pt. Steps: 4, 8, 12, 16, 24.
- Window margin: 16 pt. Sheet margin: 24 pt.
- Table row: 36 pt. Sidebar row: 28 pt.
- Radius: control 6, card 10, sheet 12, icon in a row 5.
- Sidebar: 210 pt. List pane: 620 pt. Detail pane fills the rest.

## Rules
- The `Update` button uses the accent color. In a sheet, `Update` is not the default button.
- Stale, partial and failed states change the refresh label color and add a symbol.
