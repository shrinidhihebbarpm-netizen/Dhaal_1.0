---
name: Tactical Threat Telemetry
colors:
  surface: '#0f141c'
  surface-dim: '#0f141c'
  surface-bright: '#343942'
  surface-container-lowest: '#090e16'
  surface-container-low: '#171c24'
  surface-container: '#1b2028'
  surface-container-high: '#252a33'
  surface-container-highest: '#30353e'
  on-surface: '#dee2ee'
  on-surface-variant: '#bfc8ce'
  inverse-surface: '#dee2ee'
  inverse-on-surface: '#2c3139'
  outline: '#899298'
  outline-variant: '#3f484d'
  surface-tint: '#84d0f7'
  primary: '#84d0f7'
  on-primary: '#003548'
  primary-container: '#277da1'
  on-primary-container: '#fcfdff'
  inverse-primary: '#006688'
  secondary: '#8fd2d0'
  on-secondary: '#003736'
  secondary-container: '#005553'
  on-secondary-container: '#84c7c5'
  tertiary: '#74d9b7'
  on-tertiary: '#00382a'
  tertiary-container: '#078467'
  on-tertiary-container: '#f4fff8'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c1e8ff'
  primary-fixed-dim: '#84d0f7'
  on-primary-fixed: '#001e2b'
  on-primary-fixed-variant: '#004d67'
  secondary-fixed: '#abefec'
  secondary-fixed-dim: '#8fd2d0'
  on-secondary-fixed: '#00201f'
  on-secondary-fixed-variant: '#00504e'
  tertiary-fixed: '#91f6d3'
  tertiary-fixed-dim: '#74d9b7'
  on-tertiary-fixed: '#002117'
  on-tertiary-fixed-variant: '#00513e'
  background: '#0f141c'
  on-background: '#dee2ee'
  surface-variant: '#30353e'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '700'
    lineHeight: 34px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Inter
    fontSize: 26px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: JetBrains Mono
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
  body-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  body-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '700'
    lineHeight: 14px
    letterSpacing: 0.08em
  code-telemetry:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-compact: 0.5rem
  margin: 1.5rem
  margin-mobile: 0.75rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style

This design system establishes a high-density, mission-critical defensive command atmosphere. Engineered for security engineers, threat analysts, and incident responders, the interface blends tactical HUD instrumentation with modern data-dense cyber defense ergonomics. 

The aesthetic merges utilitarian precision with targeted chromatic signals:
- **Telemetry Precision:** Monospaced, zero-ambiguity layouts optimized for scan-speed triage, packet decoding, and instantaneous alert disposition.
- **Controlled Luminescence:** Deep, light-absorbing slate bases accented by intense threat signatures drawn from a calibrated spectrum—from safe teal-green signals to high-urgency coral red alerts.
- **Instrument Brutalism:** Functional micro-borders, razor-sharp structural grids, structural hairline dividers, and minimal ornamentation prioritize situational clarity over decoration.

## Colors

The color architecture is calibrated for high-contrast dark environments, establishing explicit operational tiers:

- **Core Ground:** Dark telemetry base (`#090D14`) and elevated panel layers (`#111823`, `#182230`) construct the ambient workspace, reducing retinal fatigue during continuous surveillance.
- **Structural Containers:** Slate navy (`#577590`) and slate teal (`#4D908E`) establish mid-tone spatial segmentation, grid fences, and container boundaries.
- **Command & Primary Action:** Deep ocean cyan (`#277DA1`) serves as the primary system anchor for navigation, telemetry tracks, and selected system filters.
- **Threat Vector Spectrum:**
  - `CRITICAL / EXPLOIT`: Coral red (`#F94144`) — immediate payload mitigation required.
  - `HIGH RISK / FRAUD`: Deep orange (`#F3722C`) and tangerine (`#F8961E`).
  - `SUSPICIOUS / DRIFT`: Coral orange (`#F9844A`) and sunflower gold (`#F9C74F`).
  - `VERIFIED / SECURE`: Mint green (`#43AA8B`) and pistachio (`#90BE6D`) indicate verified signatures and hardened nodes.

## Typography

Typography enforces tactical hierarchy through dual-font structuring:

- **Structural Headers (`Inter`):** Handles section manifests, top-level dashboard metrics, and system banners with clear, legible letterforms.
- **Analytical Body & Telemetry (`JetBrains Mono`):** All analytical data, stream payloads, timestamps, IP registers, and operational metadata utilize monospaced rendering. This prevents horizontal jitter when values update in real time.
- **Micro Labels:** All metadata tags, status pills, and column indices utilize `label-caps` in uppercase format to convey immediate system state.

## Layout & Spacing

The system enforces a dense 12-column layout designed for maximum screen utility:

- **Desktop (1280px+):** Full 12-column matrix with `1rem` gutters and `1.5rem` canvas margins. Sub-panels within telemetry grids drop to `0.5rem` gutters to pack real-time graphs and feed inspectors without dead screen space.
- **Tablet (768px - 1279px):** 8-column layout. Global sidebars collapse to icon bars. Data tables shift to prioritised column views.
- **Mobile (< 767px):** 4-column layout with strict vertical stacking. Primary alert status cards float sticky at top edge; telemetry logs reflow into unified vertical streams with `margin-mobile`.
- **Rhythm:** Layout follows a strict 4px base increment. Data grids and list elements rely on `space-xs` and `space-sm` for compact information packing.

## Elevation & Depth

Depth is established primarily through tonal surfaces, translucent backdrops, and luminous border accents rather than heavy drop shadows:

- **Surface Stacking:** 
  - Base zero: `#090D14` (root viewport).
  - Level 1: `#111823` (containment zones, splitters, tables).
  - Level 2: `#182230` (elevated inspection cards, flyout drawers, active overlays).
- **Hairline Bounding:** Boundaries are separated by 1px solid outlines in muted slate (`rgba(87, 117, 144, 0.25)`). Elevated panels in alert status inherit tinted borders matching their threat code (e.g., `#F94144` at 40% alpha).
- **Targeted Glows:** Elevation on critical threat states utilizes localized neon blurs (`0 0 12px rgba(249, 65, 68, 0.25)`) to highlight active attack vectors against the dark backdrop.

## Shapes

The design system maintains a hard-edged, technical geometry:

- **Precision Radii:** Global base radius is fixed at `0.25rem` (`roundedness: 1`), conveying a structured instrument chassis. 
- **Panels & Modules:** Core containment units use `0.25rem` corners to maximize usable surface area and preserve alignment with 1px border frames.
- **Terminal Components:** Small badges and inline indicators preserve this subtle bevel rather than using pill shapes, reinforcing the non-consumer tactical personality.

## Components

### Buttons
- **Primary / Action:** Solid `#277DA1` background, white monospaced text, `0.25rem` radius, 1px cyan highlight border. Hover states illuminate background to bright ocean cyan (`#3593BC`).
- **Critical Action:** Solid `#F94144`, white text, used strictly for immediate threat termination or firewall isolation.
- **Ghost / Telemetry:** Transparent background with `rgba(87, 117, 144, 0.3)` border and muted text. Hover activates `#182230` background.

### Chips & Threat Tags
- **Base Style:** 20px fixed height, `label-caps` typography, `0.25rem` border radius, micro-padding (`2px 6px`).
- **Severity Coding:** Backgrounds set to 15% opacity tint of threat color; text and 1px border rendered in full 100% token value (`#F94144`, `#F3722C`, `#F9C74F`, `#43AA8B`).

### Data Tables & Log Streams
- **Rows:** Alternating subtle zebra striping (`#111823` to `#0D141F`) with 1px bottom border in `rgba(87, 117, 144, 0.15)`.
- **Metrics:** Tabular numbers aligned right, strict monospace rendering, dynamic color highlighting based on threat anomaly score.

### Form Inputs & Filters
- **Input Fields:** Dark slate fill (`#0B1017`), inset 1px border (`#577590`), text in `JetBrains Mono`. Focused states trigger a `#277DA1` hairline border with a soft outer glow.
- **Checkboxes & Toggles:** Square 14x14px geometry with `0.125rem` micro-radii. Active states feature solid `#277DA1` or `#43AA8B` fills with stark white icon indicators.

### Inspection Cards
- **Structure:** Modular containers enclosed with `border_hairline_hex`. Top header manifests include an uppercase terminal label, status indicator dot, and action menu.
- **Threat State Overlays:** A 2px top accent border corresponds to current telemetry status (green for nominal, amber for elevated risk, coral red for breach containment).