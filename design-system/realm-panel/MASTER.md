# Realm Console Design System

This file is the visual source of truth for the embedded Realm Panel UI.

## Direction

- Product: infrastructure operations console
- Style: calm operational, Swiss/minimal grid, dense but breathable
- Personality: reliable, precise, low-distraction
- Memorable element: three-bar signal mark and faint 32px technical grid
- Runtime constraint: no frontend framework, external font, image, CDN, or third-party script

## Color tokens

| Role | Light | Dark |
|---|---:|---:|
| Background | `#F4F7F9` | `#11191D` |
| Surface | `#FFFFFF` | `#182329` |
| Raised surface | `#F8FAFB` | `#1C292F` |
| Primary text | `#14212B` | `#E8F0F2` |
| Secondary text | `#586875` | `#A9B8BE` |
| Border | `#DCE4E9` | `#2B3A42` |
| Primary/action | `#075F65` | `#68C3BB` |
| Accent/focus | `#E36B2C` | `#E36B2C` |
| Success | `#18794E` | `#67CE99` |
| Danger | `#C43D3D` | `#FF8585` |

Color never carries status alone: every state also has a text label or icon.

## Typography

- UI: local platform sans-serif stack with Chinese system-font fallbacks
- Technical values: local `SFMono-Regular` / Consolas / Liberation Mono stack
- Scale: 11, 12, 13, 14, 16, 19, 26, 34, 44
- Weights: 400 body, 600 labels, 700 headings/actions
- Use tabular monospace figures for counts, addresses, ports, and IDs
- No remote font requests; this prevents FOIT, layout shift, and availability coupling

## Layout

- Desktop content width: 1180px maximum
- Narrow workflow width: 860px maximum
- Spacing follows a 4/8px rhythm
- Panel radius: 12px; control radius: 8px
- Breakpoints: 900px and 680px, validated at 375px minimum width
- Tables transform into labeled record rows below 680px instead of scrolling horizontally

## Components

- Buttons: 44px minimum height, visible hover/active/disabled/focus states
- Fields: visible labels, persistent helper text for endpoint formats
- Panels: thin border and restrained two-layer shadow; no decorative floating cards
- Status: dot plus explicit Online/Offline text
- Feedback: semantic success/error notice with `aria-live`
- Empty states: outline SVG, direct explanation, one useful action
- Destructive actions: separated red ghost button plus native confirmation dialog

## Motion

- 140ms fast state feedback, 220ms normal state transition
- Only color, border, opacity, and shadow transitions
- No entrance choreography or layout-moving transforms
- `prefers-reduced-motion: reduce` reduces all transition and animation durations

## Accessibility contract

- Sequential headings and semantic landmarks
- Skip link on every page
- Visible 3px focus indicator
- Associated labels for every field
- Native controls and logical DOM/tab order
- Decorative SVGs use `aria-hidden="true"`
- Touch/click targets are at least 44px high
- Password managers and paste remain supported
- Normal text targets WCAG AA 4.5:1 contrast
- UI remains usable at increased text size and 375px width without horizontal overflow

## Performance contract

- CSS and JavaScript are embedded in the Go binary and served as two cacheable resources
- No external assets, libraries, analytics, images, or font downloads
- JavaScript is progressive enhancement only; core forms work without it
- Animations avoid layout and paint-heavy properties
- Authenticated/token-bearing pages use `Cache-Control: no-store`

## Anti-patterns

- No gradients, glass decoration, blobs, emojis, excessive rounding, or generic marketing cards
- No hover-only actions or icon-only unlabeled controls
- No placeholder-only form fields
- No hidden focus rings or disabled zoom
- No animation that delays an operation or blocks input
