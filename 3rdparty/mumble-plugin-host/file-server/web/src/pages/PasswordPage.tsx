import { useState } from "react";
import Box from "@mui/material/Box";

import { authenticate, AuthError } from "../api";
import { palette } from "../theme";
import { PasswordCard } from "../components/PasswordCard";
import { PasswordForm } from "../components/PasswordForm";

/**
 * Top-level password-entry page: centres the card on the gradient backdrop and
 * owns the auth flow. On success it navigates to the ticketed download URL; on
 * failure it surfaces a friendly message and lets the user retry.
 */
export function PasswordPage() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (password: string) => {
    setError("");
    setBusy(true);
    try {
      window.location.href = await authenticate(password);
      // Keep `busy` set: the browser is navigating away.
    } catch (err) {
      setError(
        err instanceof AuthError ? err.message : "Something went wrong.",
      );
      setBusy(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        p: 3,
        background: `radial-gradient(1200px 600px at 50% -10%, ${palette.pageTop} 0%, ${palette.pageMid} 55%, ${palette.pageBottom} 100%)`,
      }}
    >
      <PasswordCard
        title="This file is protected"
        subtitle="Enter the password to open this file."
      >
        <PasswordForm onSubmit={handleSubmit} busy={busy} error={error} />
      </PasswordCard>
    </Box>
  );
}
