import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import FormHelperText from "@mui/material/FormHelperText";
import TextField from "@mui/material/TextField";

import { palette } from "../theme";

interface PasswordFormProps {
  /** Called with the entered password when the form is submitted non-empty. */
  onSubmit: (password: string) => void;
  /** True while an attempt is in flight; disables the button + field. */
  busy: boolean;
  /** Server-side error to display; a new value clears and refocuses the field. */
  error: string;
}

/**
 * Controlled password field + submit button + error line. Owns only the field
 * value; the in-flight `busy` flag and `error` text are driven by the parent so
 * the actual auth call lives outside this presentational component.
 */
export function PasswordForm({ onSubmit, busy, error }: PasswordFormProps) {
  const [password, setPassword] = useState("");
  const [emptyError, setEmptyError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  // On a fresh server error, mirror the original page: clear + refocus so the
  // user can immediately retype.
  useEffect(() => {
    if (error) {
      setPassword("");
      inputRef.current?.focus();
    }
  }, [error]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!password) {
      setEmptyError("Please enter a password.");
      return;
    }
    setEmptyError("");
    onSubmit(password);
  };

  const message = emptyError || error;

  return (
    <Box component="form" onSubmit={handleSubmit} autoComplete="off" noValidate>
      <TextField
        inputRef={inputRef}
        type="password"
        label="Password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        autoComplete="current-password"
        autoFocus
        fullWidth
        disabled={busy}
        error={Boolean(message)}
        slotProps={{
          htmlInput: { "aria-label": "Password" },
          input: { sx: { backgroundColor: palette.inputBg } },
        }}
      />
      <Button
        type="submit"
        variant="contained"
        fullWidth
        disabled={busy}
        sx={{ mt: 2, py: 1.25, fontWeight: 600, textTransform: "none" }}
      >
        {busy ? "Unlocking…" : "Unlock"}
      </Button>
      <FormHelperText
        error
        role="alert"
        sx={{ mt: 1.5, minHeight: "1.1em", textAlign: "center" }}
      >
        {message}
      </FormHelperText>
    </Box>
  );
}
