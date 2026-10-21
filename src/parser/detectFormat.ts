export type SupportedFormat = "CFD" | "CFU" | "CFA" | "UNKNOWN";

export function detectFormat(content: string): SupportedFormat {
  const text = content ?? "";
  const trimmed = text.trimStart();

  // CFA: typicky obsahuje SWIFT bloky nebo pole :01:..:07:
  if (
    trimmed.includes("{1:") ||
    trimmed.includes("{2:") ||
    trimmed.includes(":32A:") ||
    /^:0[1-7]:/m.test(trimmed)
  ) {
    return "CFA";
  }

  // CFD/CFU: hledáme první HD řádek
  const hdMatch = trimmed.match(/^HD:\s*(\d{2})\b/m);
  if (hdMatch) {
    const hdType = hdMatch[1];
    if (hdType === "11") return "CFD";
    if (hdType === "01") return "CFU";
  }

  return "UNKNOWN";
}