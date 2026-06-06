import Box from "@mui/material/Box";
import { Lock } from "lucide-react";

import { palette } from "../theme";

/** Round, softly-tinted badge holding the lock glyph at the top of the card. */
export function LockBadge() {
  return (
    <Box
      aria-hidden
      sx={{
        width: 44,
        height: 44,
        mx: "auto",
        mb: 1.75,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: "50%",
        bgcolor: palette.accentHaloBg,
        color: palette.accentSoft,
      }}
    >
      <Lock size={22} strokeWidth={2} />
    </Box>
  );
}
