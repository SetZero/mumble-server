import { createTheme } from "@mui/material/styles";

/**
 * Dark theme reproducing the look of the original hand-written password page.
 * Centralising the palette here keeps the colours reusable across any future
 * embedded pages (admin, "me", file listings, ...).
 */
export const palette = {
  pageTop: "#25304a",
  pageMid: "#141821",
  pageBottom: "#0d1016",
  cardBg: "rgba(28, 33, 44, 0.92)",
  cardBorder: "rgba(255, 255, 255, 0.08)",
  inputBg: "#11151d",
  inputBorder: "rgba(255, 255, 255, 0.12)",
  accent: "#6c8cff",
  accentSoft: "#9db2ff",
  accentHaloBg: "rgba(108, 140, 255, 0.16)",
  text: "#e7ecf3",
  textMuted: "#9aa6b8",
  danger: "#ff8a8a",
} as const;

export const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: palette.accent },
    error: { main: palette.danger },
    background: { default: palette.pageBottom, paper: palette.cardBg },
    text: { primary: palette.text, secondary: palette.textMuted },
  },
  shape: { borderRadius: 9 },
  typography: {
    fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
  },
});
