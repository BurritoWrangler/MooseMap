# MooseMap frontend

Modern, accessible web GUI for MooseMap. Vite + React 18 + TypeScript (strict).

## Develop

```bash
npm install
npm run dev      # http://localhost:5173, proxies /api + WebSocket to :8080
```

Run the backend alongside it:

```bash
cargo run -p moosemap-cli -- serve
```

## Build for production

```bash
npm run build    # emits frontend/dist/, served by the Rust server
npm run lint     # tsc --noEmit type check
```

## Accessibility

- Semantic landmarks (`header`, `nav`, `main`) and a skip link.
- All controls are keyboard-reachable with visible `:focus-visible` outlines.
- Status is conveyed by text + shape, not color alone (WCAG 1.4.1).
- A global polite ARIA live region announces real-time status changes.
- Honors `prefers-reduced-motion` and `prefers-color-scheme`.
- Color tokens target WCAG AA contrast (≥ 4.5:1 for text).

Full conformance still requires manual testing with assistive technologies and
expert review.

## Structure

- `src/api/` — typed REST client (`client.ts`) and DTO types mirroring the Rust
  server (`types.ts`).
- `src/hooks/` — `useEventStream` (WebSocket live feed with reconnect) and
  `useAnnouncer` (ARIA live region).
- `src/components/` — `NewScanForm`, `RunList`, `RunDetail` (live dashboard),
  `Pipeline`, `Badges`.
- `src/App.tsx` — layout and state wiring.
