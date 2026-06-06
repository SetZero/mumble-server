import type { ReactNode } from "react";
import Paper from "@mui/material/Paper";
import Typography from "@mui/material/Typography";

import { palette } from "../theme";
import { LockBadge } from "./LockBadge";

interface PasswordCardProps {
  title: string;
  subtitle: string;
  children: ReactNode;
}

/**
 * The frosted card shell: lock badge, title, subtitle, then arbitrary content
 * (the form). Layout only — it owns no state, so it is reusable for any
 * "enter a secret to continue" page.
 */
export function PasswordCard({ title, subtitle, children }: PasswordCardProps) {
  return (
    <Paper
      component="main"
      elevation={0}
      sx={{
        width: "100%",
        maxWidth: 380,
        p: "28px 26px 24px",
        borderRadius: "14px",
        border: `1px solid ${palette.cardBorder}`,
        backgroundColor: palette.cardBg,
        boxShadow: "0 18px 50px rgba(0, 0, 0, 0.45)",
        backdropFilter: "blur(8px)",
      }}
    >
      <LockBadge />
      <Typography
        variant="h1"
        sx={{
          m: 0,
          mb: 0.75,
          fontSize: "1.18rem",
          fontWeight: 600,
          textAlign: "center",
        }}
      >
        {title}
      </Typography>
      <Typography
        sx={{
          mb: 2.5,
          fontSize: "0.86rem",
          lineHeight: 1.4,
          textAlign: "center",
          color: "text.secondary",
        }}
      >
        {subtitle}
      </Typography>
      {children}
    </Paper>
  );
}
