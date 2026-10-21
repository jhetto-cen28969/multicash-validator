import { useMemo, useState } from "react";
import "./index.css";
import { detectFormat, type SupportedFormat } from "./parser/detectFormat";

import cfdRules from "./rules/cfd_v32.json";
import cfuRules from "./rules/cfu_v32.json";
import cfaRules from "./rules/cfa_v32.json";

type Severity = "BLOCKER" | "WARNING" | "INFO";

type RuleItem = {
  id: string;
  severity: Severity;
  enabled: boolean;
};

type RuleProfile = {
  profile: {
    id: string;
    format: "CFD" | "CFU" | "CFA";
    version: string;
    description: string;
  };
  settings?: Record<string, unknown>;
  rules: RuleItem[];
};

type ValidationIssue = {
  severity: Severity;
  code: string;
  message: string;
};

const PROFILE_BY_FORMAT: Partial<Record<SupportedFormat, RuleProfile>> = {
  CFD: cfdRules as RuleProfile,
  CFU: cfuRules as RuleProfile,
  CFA: cfaRules as RuleProfile,
};

function getRule(profile: RuleProfile, ruleId: string): RuleItem | undefined {
  return profile.rules.find((x) => x.id === ruleId);
}

function getRuleSeverity(
  profile: RuleProfile,
  ruleId: string,
  fallback: Severity = "WARNING"
): Severity {
  return getRule(profile, ruleId)?.severity ?? fallback;
}

function isRuleEnabled(profile: RuleProfile, ruleId: string): boolean {
  return !!getRule(profile, ruleId)?.enabled;
}

/* =========================
   CFA helpers + validators
   ========================= */

function hasCfaHeader(content: string, header: string): boolean {
  const re = new RegExp(`^:${header}:`, "m");
  return re.test(content);
}

function getCfaHeaderValue(content: string, header: string): string | null {
  const re = new RegExp(`^:${header}:(.*)$`, "m");
  const m = content.match(re);
  if (!m) return null;
  return (m[1] ?? "").trim();
}

function countSwiftTransactions(content: string): number {
  const matches = content.match(/\{4:/g);
  return matches ? matches.length : 0;
}

function validateCfaRequiredHeaders(
  content: string,
  profile: RuleProfile
): ValidationIssue[] {
  const required = [
    { id: "CFA.HDR.02_REQUIRED", header: "02" },
    { id: "CFA.HDR.03_REQUIRED", header: "03" },
    { id: "CFA.HDR.04_REQUIRED", header: "04" },
    { id: "CFA.HDR.05_REQUIRED", header: "05" },
    { id: "CFA.HDR.07_REQUIRED", header: "07" },
  ];

  const issues: ValidationIssue[] = [];

  for (const req of required) {
    if (!isRuleEnabled(profile, req.id)) continue;

    const exists = hasCfaHeader(content, req.header);
    if (!exists) {
      issues.push({
        severity: getRuleSeverity(profile, req.id, "BLOCKER"),
        code: req.id,
        message: `Chybí povinná hlavička :${req.header}:`,
      });
    } else {
      issues.push({
        severity: "INFO",
        code: `${req.id}.OK`,
        message: `Hlavička :${req.header}: je přítomna.`,
      });
    }
  }

  return issues;
}

function validateCfaHeader03MatchCount(
  content: string,
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "CFA.HDR.03_MATCH_COUNT";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const raw03 = getCfaHeaderValue(content, "03");
  if (!raw03) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí :03:.",
      },
    ];
  }

  const expectedCount = Number.parseInt(raw03, 10);
  if (Number.isNaN(expectedCount)) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `:03: neobsahuje platné celé číslo (hodnota: "${raw03}").`,
      },
    ];
  }

  const actualCount = countSwiftTransactions(content);

  if (expectedCount !== actualCount) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `Nesouhlasí počet transakcí: :03:=${expectedCount}, nalezeno SWIFT bloků {4:=${actualCount}.`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `Počet transakcí sedí (:03:=${expectedCount}, SWIFT bloky={4: ${actualCount}).`,
    },
  ];
}

function validateCfaHeader02AmountFormat(
  content: string,
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "CFA.HDR.02_AMOUNT_FORMAT";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const raw02 = getCfaHeaderValue(content, "02");
  if (!raw02) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí :02:.",
      },
    ];
  }

  const amountPattern = /^\d+,\d{2}$/;
  if (!amountPattern.test(raw02)) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `:02: má neplatný formát částky ("${raw02}"), očekáváno např. 12345,67.`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `:02: má platný formát částky (${raw02}).`,
    },
  ];
}

function validateCfaSwift32AFormat(
  content: string,
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "CFA.SWIFT.32A_FORMAT";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const m = content.match(/^:32A:(.+)$/m);
  if (!m) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: "Chybí pole :32A:.",
      },
    ];
  }

  const value = (m[1] ?? "").trim();
  const p = /^\d{6}[A-Z]{3}\d+,\d{2}$/;
  if (!p.test(value)) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `Pole :32A: má neplatný formát ("${value}"). Očekáváno YYMMDD + CCY + AMOUNT, např. 261016CZK123,45.`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `Pole :32A: má základně platný formát (${value}).`,
    },
  ];
}

/* =========================
   DMS (CFD/CFU) parser/spec
   ========================= */

type DmsRecord = {
  tag: string;
  rawLine: string;
  rawValue: string;
  subfields: string[];
  usedPipeSeparator: boolean;
  valueStartsWithSpace: boolean;
};

function parseUdUkFallback(rawValueWithLeadingSpaces: string): string[] {
  const trimmed = rawValueWithLeadingSpaces.trim();
  if (!trimmed) return ["", "", ""];

  const tokens = trimmed.split(/\s+/);

  const t0 = tokens[0] ?? "";
  const t1 = tokens[1] ?? "";

  const isNum = (s: string) => /^\d+$/.test(s);

  if (isNum(t0) && isNum(t1)) {
    return [t0, t1, tokens.slice(2).join(" ")];
  }

  if (isNum(t0) && !isNum(t1)) {
    return ["", t0, tokens.slice(1).join(" ")];
  }

  return ["", t0, tokens.slice(1).join(" ")];
}

function splitDmsSubfields(
  rawValue: string,
  tag?: string
): { subfields: string[]; usedPipeSeparator: boolean } {
  if (rawValue.includes("|")) {
    return {
      subfields: rawValue.split("|").map((s) => s.trim()),
      usedPipeSeparator: true,
    };
  }

  if (tag === "UD" || tag === "UK") {
    return {
      subfields: parseUdUkFallback(rawValue),
      usedPipeSeparator: false,
    };
  }

  const trimmed = rawValue.trim();
  return {
    subfields: trimmed ? trimmed.split(/\s+/) : [""],
    usedPipeSeparator: false,
  };
}

function parseDmsRecords(content: string): DmsRecord[] {
  const lines = content.split(/\r?\n/);
  const records: DmsRecord[] = [];

  for (const line of lines) {
    const m = line.match(/^([A-Z0-9]{2}):(.*)$/);
    if (!m) continue;

    const tag = m[1];
    const rawValue = (m[2] ?? "").replace(/\s+$/, "");
    const valueStartsWithSpace = /^\s/.test(rawValue);

    const { subfields, usedPipeSeparator } = splitDmsSubfields(rawValue, tag);

    records.push({
      tag,
      rawLine: line,
      rawValue,
      subfields,
      usedPipeSeparator,
      valueStartsWithSpace,
    });
  }

  return records;
}

function getFirstRecord(records: DmsRecord[], tag: string): DmsRecord | null {
  return records.find((r) => r.tag === tag) ?? null;
}

function hasAnyRecord(records: DmsRecord[], tag: string): boolean {
  return records.some((r) => r.tag === tag);
}

function getSubfield(rec: DmsRecord | null, idx: number): string {
  if (!rec) return "";
  return rec.subfields[idx] ?? "";
}

function mod11Check(num: string): boolean {
  if (!/^\d+$/.test(num)) return false;
  const weights = [1, 2, 4, 8, 5, 10, 9, 7, 3, 6];
  let sum = 0;
  let wIdx = 0;

  for (let i = num.length - 1; i >= 0; i--) {
    const d = Number(num[i]);
    sum += d * weights[wIdx % weights.length];
    wIdx++;
  }

  return sum % 11 === 0;
}

/* =========================
   DMS validators
   ========================= */

function validateDmsHdPrefix(
  format: "CFD" | "CFU",
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId =
    format === "CFD" ? "DMS.HD.PREFIX_11_FOR_CFD" : "DMS.HD.PREFIX_01_FOR_CFU";

  if (!isRuleEnabled(profile, ruleId)) return [];

  const hd = getFirstRecord(records, "HD");
  if (!hd) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: "Chybí tag HD:, nelze ověřit prefix.",
      },
    ];
  }

  const typeCode = getSubfield(hd, 0);
  const expected = format === "CFD" ? "11" : "01";

  if (typeCode !== expected) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `HD.1 (typ) nesedí. Očekáváno "${expected}", nalezeno "${typeCode || "(prázdné)"}".`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `HD.1 (typ) je správně (${expected}).`,
    },
  ];
}

function validateDmsRequiredFields(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const requiredRules = [
    { tag: "HD", ruleId: "DMS.FIELD.HD_REQUIRED" },
    { tag: "KC", ruleId: "DMS.FIELD.KC_REQUIRED" },
    { tag: "UD", ruleId: "DMS.FIELD.UD_REQUIRED" },
    { tag: "DI", ruleId: "DMS.FIELD.DI_REQUIRED" },
    { tag: "UK", ruleId: "DMS.FIELD.UK_REQUIRED" },
    { tag: "AK", ruleId: "DMS.FIELD.AK_REQUIRED" },
    { tag: "KI", ruleId: "DMS.FIELD.KI_REQUIRED" },
    { tag: "EC", ruleId: "DMS.FIELD.EC_REQUIRED" },
    { tag: "ZK", ruleId: "DMS.FIELD.ZK_REQUIRED" },
    { tag: "AV", ruleId: "DMS.FIELD.AV_REQUIRED" },
  ];

  const issues: ValidationIssue[] = [];

  for (const req of requiredRules) {
    if (!isRuleEnabled(profile, req.ruleId)) continue;

    const exists = hasAnyRecord(records, req.tag);
    if (!exists) {
      issues.push({
        severity: getRuleSeverity(profile, req.ruleId, "BLOCKER"),
        code: req.ruleId,
        message: `Chybí povinný tag ${req.tag}:`,
      });
    } else {
      issues.push({
        severity: "INFO",
        code: `${req.ruleId}.OK`,
        message: `Povinný tag ${req.tag}: je přítomen.`,
      });
    }
  }

  return issues;
}

function validateDmsKcAmountNumeric(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.KC.AMOUNT_NUMERIC";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const kc = getFirstRecord(records, "KC");
  if (!kc) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí KC:.",
      },
    ];
  }

  const amount = getSubfield(kc, 0);
  const ok = /^\d+(?:[,.]\d{1,2})?$/.test(amount);

  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `KC.1 neobsahuje validní číselnou částku (hodnota: "${amount || kc.rawValue.trim()}").`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `KC.1 obsahuje validní částku (${amount}).`,
    },
  ];
}

function validateDmsHdDateRrMmDd(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.DATE.HD_RRMMDD";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const hd = getFirstRecord(records, "HD");
  if (!hd) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí HD:.",
      },
    ];
  }

  const datePart = getSubfield(hd, 1);
  const ok = /^\d{6}$/.test(datePart);

  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `HD.2 nemá formát RRMMDD (hodnota: "${datePart || "(prázdné)"}").`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `HD.2 má formát RRMMDD (${datePart}).`,
    },
  ];
}

function validateDmsEcFormatFixed(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.EC.FORMAT_FIXED";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const ec = getFirstRecord(records, "EC");
  if (!ec) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí EC:.",
      },
    ];
  }

  const value = getSubfield(ec, 0);
  const ok = /^\d{1,4}$/.test(value);

  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `EC má neplatný formát ("${value}"), očekáváno 1-4 číslice (např. 0, 0008).`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `EC má platný numerický formát (${value}).`,
    },
  ];
}

function validateDmsBankCodeFormat(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.BANKCODE.FORMAT";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const hd = getFirstRecord(records, "HD");
  const bankCode = getSubfield(hd, 4);

  if (!bankCode) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: "Nelze ověřit bank code: chybí HD.5 (kód banky partnera).",
      },
    ];
  }

  const ok = /^\d{4}$/.test(bankCode);
  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `HD.5 nemá formát 4 číslic (hodnota: "${bankCode}").`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `HD.5 má správný formát kódu banky (${bankCode}).`,
    },
  ];
}

function validateDmsEmptyPrefixExplicitMarker(
  rec: DmsRecord | null,
  tag: "UD" | "UK",
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = `DMS.ACCOUNT.${tag}_PREFIX_EMPTY_MARKED`;
  const enabled = getRule(profile, ruleId)?.enabled ?? true;
  if (!enabled) return [];

  if (!rec) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: `Kontrola přeskočena: chybí ${tag}:.`,
      },
    ];
  }

  const prefix = getSubfield(rec, 0);
  if (prefix) {
    return [
      {
        severity: "INFO",
        code: `${ruleId}.OK`,
        message: `${tag}.1 (prefix) je vyplněn.`,
      },
    ];
  }

  const explicitlyMarked =
    (rec.usedPipeSeparator && /^\s*\|/.test(rec.rawValue)) ||
    (!rec.usedPipeSeparator && rec.valueStartsWithSpace);

  if (!explicitlyMarked) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "WARNING"),
        code: ruleId,
        message: `${tag}.1 je prázdné, ale není explicitně vyznačeno (očekává se např. "${tag}:|..." nebo mezera hned po "${tag}:").`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `${tag}.1 je prázdné a je explicitně vyznačeno dle formátu.`,
    },
  ];
}

function validateDmsAccountPrefixMod11(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.ACCOUNT.PREFIX_MOD11";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const uk = getFirstRecord(records, "UK");
  if (!uk) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí UK:.",
      },
    ];
  }

  const prefix = getSubfield(uk, 0);
  if (!prefix) {
    return [
      {
        severity: "INFO",
        code: `${ruleId}.OK`,
        message: "Prefix účtu (UK.1) není uveden (akceptováno).",
      },
    ];
  }

  if (!/^\d+$/.test(prefix)) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `Prefix účtu (UK.1) není numerický (${prefix}).`,
      },
    ];
  }

  const ok = mod11Check(prefix);
  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `Prefix účtu (UK.1) neprošel MOD11 (${prefix}).`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `Prefix účtu (UK.1) prošel MOD11 (${prefix}).`,
    },
  ];
}

function validateDmsAccountPayerMod11(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.ACCOUNT.PAYER_MOD11";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const ud = getFirstRecord(records, "UD");
  if (!ud) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí UD:.",
      },
    ];
  }

  const acc = getSubfield(ud, 1);
  if (!acc) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: "UD.2 (číslo účtu) je prázdné.",
      },
    ];
  }

  if (!/^\d+$/.test(acc)) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `UD.2 není numerické (${acc}).`,
      },
    ];
  }

  const ok = mod11Check(acc);
  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `Účet v UD.2 neprošel MOD11 (${acc}).`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `Účet v UD.2 prošel MOD11 (${acc}).`,
    },
  ];
}

function validateDmsAccountBenefMod11(
  records: DmsRecord[],
  profile: RuleProfile
): ValidationIssue[] {
  const ruleId = "DMS.ACCOUNT.BENEF_MOD11";
  if (!isRuleEnabled(profile, ruleId)) return [];

  const uk = getFirstRecord(records, "UK");
  if (!uk) {
    return [
      {
        severity: "WARNING",
        code: `${ruleId}.SKIP`,
        message: "Kontrola přeskočena: chybí UK:.",
      },
    ];
  }

  const acc = getSubfield(uk, 1);
  if (!acc) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: "UK.2 (číslo účtu partnera) je prázdné.",
      },
    ];
  }

  if (!/^\d+$/.test(acc)) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `UK.2 není numerické (${acc}).`,
      },
    ];
  }

  const ok = mod11Check(acc);
  if (!ok) {
    return [
      {
        severity: getRuleSeverity(profile, ruleId, "BLOCKER"),
        code: ruleId,
        message: `Účet v UK.2 neprošel MOD11 (${acc}).`,
      },
    ];
  }

  return [
    {
      severity: "INFO",
      code: `${ruleId}.OK`,
      message: `Účet v UK.2 prošel MOD11 (${acc}).`,
    },
  ];
}

function validateDms(
  format: "CFD" | "CFU",
  content: string,
  profile: RuleProfile
): ValidationIssue[] {
  const records = parseDmsRecords(content);
  const issues: ValidationIssue[] = [];

  const ud = getFirstRecord(records, "UD");
  const uk = getFirstRecord(records, "UK");

  issues.push(...validateDmsHdPrefix(format, records, profile));
  issues.push(...validateDmsRequiredFields(records, profile));
  issues.push(...validateDmsKcAmountNumeric(records, profile));

  issues.push(...validateDmsHdDateRrMmDd(records, profile));
  issues.push(...validateDmsEcFormatFixed(records, profile));
  issues.push(...validateDmsBankCodeFormat(records, profile));

  issues.push(...validateDmsEmptyPrefixExplicitMarker(ud, "UD", profile));
  issues.push(...validateDmsEmptyPrefixExplicitMarker(uk, "UK", profile));

  issues.push(...validateDmsAccountPrefixMod11(records, profile));
  issues.push(...validateDmsAccountPayerMod11(records, profile));
  issues.push(...validateDmsAccountBenefMod11(records, profile));

  return issues;
}

/* =========================
   Main validation switch
   ========================= */

function validateByProfile(
  format: SupportedFormat,
  content: string
): ValidationIssue[] {
  if (!content.trim()) return [];

  const profile = PROFILE_BY_FORMAT[format];
  if (!profile) {
    return [
      {
        severity: "WARNING",
        code: "FMT.UNKNOWN",
        message:
          "Formát se nepodařilo rozpoznat nebo pro něj chybí profil pravidel.",
      },
    ];
  }

  const enabledRules = profile.rules.filter((r) => r.enabled);

  const result: ValidationIssue[] = [
    {
      severity: "INFO",
      code: "PROFILE.SELECTED",
      message: `Použit profil ${profile.profile.id} (${profile.profile.description})`,
    },
    {
      severity: "INFO",
      code: "RULES.COUNT",
      message: `Aktivních pravidel: ${enabledRules.length}`,
    },
  ];

  if (format === "CFA") {
    result.push(...validateCfaRequiredHeaders(content, profile));
    result.push(...validateCfaHeader03MatchCount(content, profile));
    result.push(...validateCfaHeader02AmountFormat(content, profile));
    result.push(...validateCfaSwift32AFormat(content, profile));
    return result;
  }

  if (format === "CFD" || format === "CFU") {
    result.push(...validateDms(format, content, profile));
    return result;
  }

  return result;
}

function App() {
  const [fileName, setFileName] = useState<string>("");
  const [content, setContent] = useState<string>("");

  const format: SupportedFormat = useMemo(() => detectFormat(content), [content]);
  const issues = useMemo(
    () => validateByProfile(format, content),
    [format, content]
  );

  async function onFileChange(file: File | null) {
    if (!file) return;
    setFileName(file.name);
    const text = await file.text();
    setContent(text);
  }

  return (
    <div className="app">
      <h1>MultiCash Validator</h1>

      <label className="upload">
        Vyber soubor:
        <input
          type="file"
          onChange={(e) => onFileChange(e.target.files?.[0] ?? null)}
        />
      </label>

      <div className="meta">
        <p>
          <strong>Soubor:</strong> {fileName || "-"}
        </p>
        <p>
          <strong>Detekovaný formát:</strong> {format}
        </p>
      </div>

      <div className="split">
        <section className="leftPane">
          <h2>Obsah souboru</h2>
          <pre>{content || "Zatím nebyl načten žádný soubor."}</pre>
        </section>

        <section className="rightPane">
          <h2>Výsledky validace</h2>
          {issues.length === 0 ? (
            <p>Žádné výsledky (nahraj soubor).</p>
          ) : (
            <ul className="issues">
              {issues.map((i, idx) => (
                <li key={`${i.code}-${idx}`} className={`sev-${i.severity}`}>
                  <strong>{i.severity}</strong> · {i.code}
                  <br />
                  <span>{i.message}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}

export default App;