import type {
  ScenarioInfo, InputsView, ConstraintsView, CertifyResult,
  TimelineView, CertsView, VerifyView,
} from "./types";

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`GET ${url} -> ${r.status}`);
  return (await r.json()) as T;
}

async function post<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`POST ${url} -> ${r.status}`);
  return (await r.json()) as T;
}

export const getScenarios = () => get<ScenarioInfo[]>("/api/scenarios");
export const getInputs = (d: string) => get<InputsView>(`/api/inputs/${d}`);
export const getConstraints = (d: string) => get<ConstraintsView>(`/api/constraints/${d}`);
export const certify = (d: string) => post<CertifyResult>(`/api/certify/${d}`, {});
export const getTimeline = (d: string) => get<TimelineView>(`/api/timeline/${d}`);
export const getCertificates = (d: string) => get<CertsView>(`/api/certificates/${d}`);
export const verify = (
  planCert: Record<string, unknown>,
  rulePackCert?: Record<string, unknown> | null,
  signerKey?: string | null,
) =>
  post<VerifyView>("/api/verify", {
    plan_cert: planCert,
    rule_pack_cert: rulePackCert ?? null,
    signer_key: signerKey ?? null,
  });
