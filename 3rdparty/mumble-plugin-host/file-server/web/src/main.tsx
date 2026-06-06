import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import CssBaseline from "@mui/material/CssBaseline";
import { ThemeProvider } from "@mui/material/styles";

import { theme } from "./theme";
import { PasswordPage } from "./pages/PasswordPage";

const container = document.getElementById("root");
if (!container) {
  throw new Error("missing #root mount node");
}

createRoot(container).render(
  <StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <PasswordPage />
    </ThemeProvider>
  </StrictMode>,
);
