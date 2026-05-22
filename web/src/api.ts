import type { FullCheckReport } from "./types";

export async function runFullCheck(target: string, insecure: boolean): Promise<FullCheckReport> {
  const response = await fetch("/api/check/full", {
    body: JSON.stringify({ target, insecure }),
    headers: {
      "Content-Type": "application/json",
    },
    method: "POST",
  });

  const payload = (await response.json()) as FullCheckReport | { error?: string };
  if (!response.ok) {
    throw new Error("error" in payload && payload.error ? payload.error : "check failed");
  }
  return payload as FullCheckReport;
}
