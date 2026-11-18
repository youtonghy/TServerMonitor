import type {
  Alert, AgentRun, AgentRunDetail, ContainerInfo, Conversation, ConversationDetail, NewConversation, ContainerLogsResponse, DailyErrorCount, DbStatus,
  Finding, LogCluster, LogRatesResponse, LogSource, MetricsRange, MetricsResponse, ModelsRequest, PortInfo,
  ChannelInput, ChannelsResponse, Prompt, PromptInput, ProviderInput, ProvidersResponse, TaskInput, TasksResponse, Report, ReportKind, ReportSummary, Route, RoutingResponse, Snapshot,
  StatusResponse, TriggerResponse,
} from "./types";

export const MOCK = import.meta.env.VITE_MOCK === "1";

const BASE = "/api/v1";
const TOKEN_KEY = "tsm_token";

/** An HTTP error with the status code and the server's `{ error }` message when present. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// Token storage. The token lives in localStorage so the SSE stream and every fetch can read it.

type Listener = () => void;
const tokenListeners = new Set<Listener>();
const unauthorizedListeners = new Set<Listener>();

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch (error) {
    console.error("无法保存访问令牌", error);
  }
  tokenListeners.forEach(listener => listener());
}

/** Called whenever the token changes, so the stream can reconnect and failed queries can retry. */
export function onTokenChange(listener: Listener): () => void {
  tokenListeners.add(listener);
  return () => tokenListeners.delete(listener);
}

/** Called when any request gets a 401, so the app can ask for a token. */
export function onUnauthorized(listener: Listener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

export function notifyUnauthorized(): void {
  unauthorizedListeners.forEach(listener => listener());
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init?.body) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "无法连接到服务器，请检查守护进程是否在运行");
  }

  if (!response.ok) {
    let message = `请求失败 (${response.status})`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "error" in body && typeof body.error === "string") message = body.error;
    } catch {
      // The body was not JSON; keep the status message.
    }
    if (response.status === 401) notifyUnauthorized();
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export interface Api {
  status(): Promise<StatusResponse>;
  snapshot(): Promise<Snapshot>;
  metrics(range: MetricsRange): Promise<MetricsResponse>;
  containers(): Promise<ContainerInfo[]>;
  containerLogs(id: string, tail?: number): Promise<ContainerLogsResponse>;
  logSources(): Promise<LogSource[]>;
  logRates(range?: string): Promise<LogRatesResponse>;
  logClusters(filter?: { source?: string; level?: string; limit?: number }): Promise<LogCluster[]>;
  dailyErrors(days?: number): Promise<DailyErrorCount[]>;
  findings(includeResolved?: boolean): Promise<Finding[]>;
  ports(): Promise<PortInfo[]>;
  db(): Promise<DbStatus[]>;
  alerts(status?: "open" | "all", limit?: number): Promise<Alert[]>;
  reports(kind?: ReportKind | "", limit?: number): Promise<ReportSummary[]>;
  latestReport(kind?: ReportKind): Promise<Report>;
  report(id: number): Promise<Report>;
  agentRuns(limit?: number): Promise<AgentRun[]>;
  agentRun(id: string): Promise<AgentRunDetail>;
  trigger(kind: ReportKind): Promise<TriggerResponse>;
  providers(): Promise<ProvidersResponse>;
  createProvider(input: ProviderInput): Promise<{ id: string }>;
  updateProvider(id: string, input: ProviderInput): Promise<{ id: string }>;
  deleteProvider(id: string): Promise<{ ok: true }>;
  listModels(req: ModelsRequest): Promise<{ models: string[] }>;
  routing(): Promise<RoutingResponse>;
  saveRouting(routes: Route[]): Promise<RoutingResponse>;
  conversations(kind?: "chat" | "task" | "", limit?: number): Promise<Conversation[]>;
  conversation(id: string): Promise<ConversationDetail>;
  createConversation(input: NewConversation): Promise<{ id: string; run_id: string | null }>;
  sendMessage(id: string, text: string): Promise<{ run_id: string }>;
  deleteConversation(id: string): Promise<{ ok: true }>;
  cancelRun(runId: string): Promise<{ ok: true }>;
  tasks(): Promise<TasksResponse>;
  createTask(input: TaskInput): Promise<{ id: string }>;
  updateTask(id: string, input: TaskInput): Promise<{ id: string }>;
  deleteTask(id: string): Promise<{ ok: true }>;
  runTask(id: string): Promise<{ run_id: string | null; deferred: boolean }>;
  prompts(): Promise<Prompt[]>;
  createPrompt(input: PromptInput): Promise<{ id: string }>;
  updatePrompt(id: string, input: PromptInput): Promise<{ id: string }>;
  deletePrompt(id: string): Promise<{ ok: true }>;
  generatePrompt(description: string): Promise<{ body: string }>;
  ackAlert(id: number): Promise<Alert>;
  silenceAlert(id: number, minutes: number): Promise<Alert>;
  closeAlert(id: number): Promise<Alert>;
  channels(): Promise<ChannelsResponse>;
  createChannel(input: ChannelInput): Promise<{ id: string }>;
  updateChannel(id: string, input: ChannelInput): Promise<{ id: string }>;
  deleteChannel(id: string): Promise<{ ok: true }>;
  testChannel(id: string): Promise<{ ok: true }>;
}

const json = (method: string, body: unknown): RequestInit => ({ method, body: JSON.stringify(body) });

const httpApi: Api = {
  status: () => request("/status"),
  snapshot: () => request("/snapshot"),
  metrics: range => request(`/metrics${query({ range })}`),
  containers: () => request("/containers"),
  containerLogs: (id, tail = 200) => request(`/containers/${encodeURIComponent(id)}/logs${query({ tail })}`),
  logSources: () => request("/logs/sources"),
  logRates: (range = "24h") => request(`/logs/rates${query({ range })}`),
  logClusters: (filter = {}) => request(`/logs/clusters${query({ source: filter.source, level: filter.level, limit: filter.limit ?? 100 })}`),
  dailyErrors: (days = 365) => request(`/logs/daily-errors${query({ days })}`),
  findings: (includeResolved = false) => request(`/findings${query({ include_resolved: includeResolved })}`),
  ports: () => request("/ports"),
  db: () => request("/db"),
  alerts: (status = "open", limit = 100) => request(`/alerts${query({ status, limit })}`),
  reports: (kind = "", limit = 50) => request(`/reports${query({ kind, limit })}`),
  latestReport: kind => request(`/reports/latest${query({ kind })}`),
  report: id => request(`/reports/${id}`),
  agentRuns: (limit = 50) => request(`/agent/runs${query({ limit })}`),
  agentRun: id => request(`/agent/runs/${encodeURIComponent(id)}`),
  trigger: kind => request("/agent/trigger", { method: "POST", body: JSON.stringify({ kind }) }),
  providers: () => request("/settings/providers"),
  createProvider: input => request("/settings/providers", json("POST", input)),
  updateProvider: (id, input) => request(`/settings/providers/${encodeURIComponent(id)}`, json("PATCH", input)),
  deleteProvider: id => request(`/settings/providers/${encodeURIComponent(id)}`, { method: "DELETE" }),
  listModels: req => request("/settings/models", json("POST", req)),
  routing: () => request("/settings/routing"),
  saveRouting: routes => request("/settings/routing", json("PUT", { routes })),
  conversations: (kind = "", limit = 100) => request(`/conversations${query({ kind, limit })}`),
  conversation: id => request(`/conversations/${encodeURIComponent(id)}`),
  createConversation: input => request("/conversations", json("POST", input)),
  sendMessage: (id, text) => request(`/conversations/${encodeURIComponent(id)}/messages`, json("POST", { text })),
  deleteConversation: id => request(`/conversations/${encodeURIComponent(id)}`, { method: "DELETE" }),
  cancelRun: runId => request(`/agent/runs/${encodeURIComponent(runId)}/cancel`, { method: "POST" }),
  tasks: () => request("/tasks"),
  createTask: input => request("/tasks", json("POST", input)),
  updateTask: (id, input) => request(`/tasks/${encodeURIComponent(id)}`, json("PATCH", input)),
  deleteTask: id => request(`/tasks/${encodeURIComponent(id)}`, { method: "DELETE" }),
  runTask: id => request(`/tasks/${encodeURIComponent(id)}/run`, { method: "POST" }),
  prompts: () => request("/prompts"),
  createPrompt: input => request("/prompts", json("POST", input)),
  updatePrompt: (id, input) => request(`/prompts/${encodeURIComponent(id)}`, json("PATCH", input)),
  deletePrompt: id => request(`/prompts/${encodeURIComponent(id)}`, { method: "DELETE" }),
  generatePrompt: description => request("/prompts/generate", json("POST", { description })),
  ackAlert: id => request(`/alerts/${id}/ack`, { method: "POST" }),
  silenceAlert: (id, minutes) => request(`/alerts/${id}/silence`, json("POST", { minutes })),
  closeAlert: id => request(`/alerts/${id}/close`, { method: "POST" }),
  channels: () => request("/settings/notify"),
  createChannel: input => request("/settings/notify", json("POST", input)),
  updateChannel: (id, input) => request(`/settings/notify/${encodeURIComponent(id)}`, json("PATCH", input)),
  deleteChannel: id => request(`/settings/notify/${encodeURIComponent(id)}`, { method: "DELETE" }),
  testChannel: id => request(`/settings/notify/${encodeURIComponent(id)}/test`, { method: "POST" }),
};

/**
 * In mock mode every call goes to the generated dataset. The mock module is loaded lazily, and because
 * MOCK is a build-time constant the import is dropped from production builds.
 */
function mockApi(): Api {
  const load = () => import("./mock").then(module => module.mockApi);
  return new Proxy({} as Api, {
    get: (_target, key: keyof Api) => (...args: unknown[]) =>
      load().then(api => (api[key] as (...a: unknown[]) => Promise<unknown>)(...args)),
  });
}

export const api: Api = import.meta.env.VITE_MOCK === "1" ? mockApi() : httpApi;

/** URL for the shared EventSource. EventSource cannot send headers, so the token goes in the query. */
export function streamUrl(): string {
  const token = getToken();
  return `${BASE}/stream${token ? query({ token }) : ""}`;
}
