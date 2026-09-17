import { useCallback, useEffect, useState } from "react";

const views = {
  signIn: "signIn",
  signUp: "signUp",
  forgot: "forgot",
  dashboard: "dashboard"
};

const apiBaseUrl = (import.meta.env.VITE_API_URL || "").replace(/\/+$/, "");

function apiUrl(path) {
  return `${apiBaseUrl}${path.startsWith("/") ? path : `/${path}`}`;
}

async function request(path, options) {
  const token = window.localStorage.getItem("access_token") || window.localStorage.getItem("token");
  const response = await fetch(apiUrl(path), {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options?.headers ?? {})
    },
    ...options
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.detail || "Something went wrong. Please try again.");
  }
  return body;
}

function reportAttributes(payload) {
  const candidates = [
    payload?.data?.attributes,
    payload?.attributes,
    payload?.report?.data?.attributes,
    payload?.report?.attributes,
    payload?.report
  ];
  return candidates.find((value) => value && typeof value === "object") || {};
}

function readableReport(report) {
  const attributes = reportAttributes(report);
  const stats =
    attributes.last_analysis_stats &&
    typeof attributes.last_analysis_stats === "object"
      ? attributes.last_analysis_stats
      : {};
  const results =
    attributes.last_analysis_results &&
    typeof attributes.last_analysis_results === "object"
      ? attributes.last_analysis_results
      : attributes.results && typeof attributes.results === "object"
        ? attributes.results
        : {};
  const derivedStats = Object.values(results).reduce((counts, result) => {
    const category =
      typeof result?.category === "string"
        ? result.category.toLowerCase()
        : "";
    if (category) {
      counts[category] = (counts[category] || 0) + 1;
    }
    return counts;
  }, {});
  if (Object.keys(stats).length === 0 && Object.keys(derivedStats).length === 0) {
    throw new Error("The scan completed without returning analysis results.");
  }
  const numericStats = { ...derivedStats };
  Object.entries(stats).forEach(([key, value]) => {
    const numericValue = Number(value);
    if (Number.isFinite(numericValue)) {
      numericStats[key] = numericValue;
    }
  });
  numericStats.harmless = numericStats.harmless || 0;
  numericStats.suspicious = numericStats.suspicious || 0;
  numericStats.malicious = numericStats.malicious || 0;
  const threats = numericStats.malicious + numericStats.suspicious;
  const total = Object.values(numericStats).reduce(
    (sum, value) => sum + (Number(value) || 0),
    0
  );
  const engineResults = Object.entries(results)
    .filter(([, result]) => {
      const category =
        typeof result?.category === "string"
          ? result.category.toLowerCase()
          : "";
      return category === "malicious" || category === "suspicious";
    })
    .map(([engine, result]) => ({
      engine,
      category: result.category.toLowerCase(),
      result: result.result || "Flagged"
    }));

  if (threats > 0) {
    return {
      label: "Needs attention",
      detail: `${threats} security service${threats === 1 ? "" : "s"} flagged this item. Avoid opening or sharing it.`,
      stats: numericStats,
      total,
      engineResults
    };
  }
  return {
    label: "No threats found",
    detail: `${numericStats.harmless} security services found no threat. Results can change as more services finish.`,
    stats: numericStats,
    total,
    engineResults
  };
}

async function completedReport(payload) {
  const attributes = reportAttributes(payload);
  const hasStats =
    attributes.last_analysis_stats &&
    typeof attributes.last_analysis_stats === "object" &&
    Object.keys(attributes.last_analysis_stats).length > 0;
  const hasResults =
    [attributes.results, attributes.last_analysis_results].some(
      (value) =>
        value &&
        typeof value === "object" &&
        Object.keys(value).length > 0
    );
  if (hasStats || hasResults) {
    return payload;
  }

  const analysisId =
    payload?.data?.id ||
    payload?.id ||
    payload?.report?.data?.id ||
    payload?.report?.id;
  if (!analysisId) {
    throw new Error("The scan response did not include a usable analysis report.");
  }

  const deadline = Date.now() + 600000;
  while (Date.now() < deadline) {
    const report = await request(`/virustotal/analyses/${encodeURIComponent(analysisId)}/report`);
    if (report?.status === "pending") {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      continue;
    }
    return report;
  }
  throw new Error("VirusTotal analysis did not complete within the allowed time.");
}

function ScanResult({ result }) {
  if (!result) return null;
  return (
    <div className={`mt-5 rounded-2xl border p-4 ${result.error ? "border-red-200 bg-red-50" : "border-indigo-100 bg-indigo-50"}`}>
      <p className={`font-semibold ${result.error ? "text-red-700" : "text-indigo-900"}`}>
        {result.error ? "Scan could not be completed" : result.summary.label}
      </p>
      <p className={`mt-1 text-sm ${result.error ? "text-red-600" : "text-indigo-700"}`}>
        {result.error || result.summary.detail}
      </p>
      {!result.error && (
        <div className="mt-4">
          <div className="grid grid-cols-2 gap-2 text-center sm:grid-cols-4">
            {[
              ["Checked", result.summary.total],
              ["Safe", result.summary.stats.harmless || 0],
              ["Suspicious", result.summary.stats.suspicious || 0],
              ["Malicious", result.summary.stats.malicious || 0]
            ].map(([label, value]) => (
              <div className="rounded-xl bg-white/70 px-2 py-3" key={label}>
                <p className="text-lg font-bold text-slate-900">{value}</p>
                <p className="text-xs text-slate-500">{label}</p>
              </div>
            ))}
          </div>
          {result.summary.engineResults.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Services that flagged it</p>
              <ul className="mt-2 space-y-2">
                {result.summary.engineResults.map((finding) => (
                  <li className="flex items-center justify-between rounded-xl bg-white/70 px-3 py-2 text-sm" key={`${finding.engine}-${finding.result}`}>
                    <span className="font-medium text-slate-700">{finding.engine}</span>
                    <span className="text-red-600">{finding.result}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatReportModal({ report, onClose }) {
  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === "Escape") onClose();
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!report) return null;

  return (
    <div
      aria-labelledby="threat-report-title"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      role="dialog"
    >
      <section className="max-h-[90vh] w-full  overflow-y-auto rounded-3xl bg-white p-6 shadow-2xl sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-amber-600">Threat report</p>
            <h2 className="mt-2 text-2xl font-bold text-slate-900" id="threat-report-title">Security issues found</h2>
            <p className="mt-2 break-all text-sm text-slate-500">{report.target}</p>
          </div>
          <button
            aria-label="Close threat report"
            className="rounded-xl p-2 text-2xl leading-none text-slate-400 hover:bg-slate-100 hover:text-slate-700"
            onClick={onClose}
            type="button"
          >
            ×
          </button>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            ["Checked", report.total],
            ["Safe", report.stats?.harmless || 0],
            ["Suspicious", report.stats?.suspicious || 0],
            ["Malicious", report.stats?.malicious || 0]
          ].map(([label, value]) => (
            <div className="rounded-2xl bg-slate-50 px-3 py-4 text-center" key={label}>
              <p className="text-xl font-bold text-slate-900">{value}</p>
              <p className="mt-1 text-xs text-slate-500">{label}</p>
            </div>
          ))}
        </div>

        <div className="mt-6">
          <h3 className="text-sm font-bold uppercase tracking-wide text-slate-500">Services that flagged this item</h3>
          <ul className="mt-3 space-y-3">
            {report.engineResults.map((finding) => (
              <li className="rounded-2xl border border-amber-100 bg-amber-50 p-4" key={`${finding.engine}-${finding.result}`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold text-slate-800">{finding.engine}</span>
                  <span className="rounded-full bg-red-100 px-2.5 py-1 text-xs font-semibold capitalize text-red-700">{finding.category}</span>
                </div>
                <p className="mt-2 text-sm text-slate-600">{finding.result}</p>
              </li>
            ))}
          </ul>
        </div>

        <p className="mt-6 rounded-2xl bg-red-50 p-4 text-sm leading-6 text-red-700">
          Avoid opening or sharing this item until you can verify that these findings are false positives.
        </p>
      </section>
    </div>
  );
}

function Dashboard({ onSignOut }) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedThreatReport, setSelectedThreatReport] = useState(null);

  const loadHistory = useCallback(async () => {
    const records = await request("/virustotal/history");
    setHistory(
      records.map((record) => ({
        id: record.id,
        kind: record.kind,
        target: record.target,
        createdAt: record.created_at,
        ...readableReport(record.report)
      }))
    );
  }, []);

  useEffect(() => {
    loadHistory().catch(() => setHistory([]));
  }, [loadHistory]);

  async function scanUrl(event) {
    event.preventDefault();
    setBusy("url");
    setResult(null);
    try {
      const submission = await request("/virustotal/urls", {
        method: "POST",
        body: JSON.stringify({ url })
      });
      const report = await completedReport(submission);
      const summary = readableReport(report);
      setResult({ summary });
      await loadHistory();
      setUrl("");
    } catch (error) {
      setResult({ error: error.message });
    } finally {
      setBusy("");
    }
  }

  async function scanFile(event) {
    event.preventDefault();
    if (!file) return;
    setBusy("file");
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch(apiUrl("/virustotal/files"), {
        method: "POST",
        credentials: "include",
        body: formData
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || "The file could not be scanned.");
      const report = await completedReport(body);
      const summary = readableReport(report);
      setResult({ summary });
      await loadHistory();
      setFile(null);
      event.target.reset();
    } catch (error) {
      setResult({ error: error.message });
    } finally {
      setBusy("");
    }
  }

  return (
    <main className="min-h-screen w-full max-w-none bg-slate-950 px-4 py-8 text-slate-900 sm:px-6">
      <div className="mx-auto w-full min-w-0 max-w-7xl">
        <header className="mb-8 flex flex-wrap items-center justify-between gap-4 text-white">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-indigo-300">Secure Auth</p>
            <h1 className="mt-2 text-3xl font-bold">Security dashboard</h1>
            <p className="mt-2 text-slate-400">Check a file or website for known security threats.</p>
          </div>
          <button className="rounded-xl border border-white/20 px-4 py-2 text-sm font-semibold hover:bg-white/10" onClick={onSignOut} type="button">
            Sign out
          </button>
        </header>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
          <section className="grid gap-6 md:grid-cols-2">
            <div className="rounded-3xl bg-white p-6 shadow-2xl shadow-black/20">
              <div className="mb-6 flex items-start justify-between">
                <div>
                  <p className="text-sm font-semibold text-indigo-600">01</p>
                  <h2 className="mt-1 text-2xl font-bold">File Check</h2>
                  <p className="mt-2 text-sm text-slate-500">Upload a file to see whether it looks unsafe.</p>
                </div>
                <span className="rounded-xl bg-indigo-50 px-3 py-2 text-xl">↑</span>
              </div>
              <form onSubmit={scanFile}>
                <label className="flex min-h-36 cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-slate-200 bg-slate-50 px-4 text-center hover:border-indigo-300">
                  <span className="font-medium text-slate-700">{file ? file.name : "Choose a file"}</span>
                  <span className="mt-2 text-xs text-slate-400">Your file is checked by VirusTotal.</span>
                  <input className="sr-only" type="file" onChange={(event) => setFile(event.target.files[0] || null)} />
                </label>
                <button className="mt-5 w-full rounded-xl bg-indigo-600 px-4 py-3 font-semibold text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50" disabled={!file || busy !== ""} type="submit">
                  {busy === "file" ? "Checking file..." : "Check file"}
                </button>
              </form>
            </div>

            <div className="rounded-3xl bg-white p-6 shadow-2xl shadow-black/20">
              <div className="mb-6 flex items-start justify-between">
                <div>
                  <p className="text-sm font-semibold text-violet-600">02</p>
                  <h2 className="mt-1 text-2xl font-bold">URL Check</h2>
                  <p className="mt-2 text-sm text-slate-500">Paste a website address to check its reputation.</p>
                </div>
                <span className="rounded-xl bg-violet-50 px-3 py-2 text-xl">↗</span>
              </div>
              <form onSubmit={scanUrl}>
                <label className="block text-sm font-medium text-slate-700" htmlFor="scan-url">Website address</label>
                <input id="scan-url" className="mt-2 w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100" type="url" required placeholder="https://example.com" value={url} onChange={(event) => setUrl(event.target.value)} />
                <button className="mt-5 w-full rounded-xl bg-violet-600 px-4 py-3 font-semibold text-white hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-50" disabled={busy !== ""} type="submit">
                  {busy === "url" ? "Checking website..." : "Check website"}
                </button>
              </form>
            </div>
            <div className="md:col-span-2">
              <ScanResult result={result} />
            </div>
          </section>

          <aside className="rounded-3xl bg-white p-6 shadow-2xl shadow-black/20">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold">Scan history</h2>
                <p className="mt-1 text-sm text-slate-500">Your recent checks</p>
              </div>
              <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-500">{history.length}</span>
            </div>
            {history.length === 0 ? (
              <p className="mt-8 rounded-2xl bg-slate-50 p-4 text-sm leading-6 text-slate-500">Your completed checks will appear here.</p>
            ) : (
              <ul className="mt-6 space-y-3">
                {history.map((item) => (
                  <li className="rounded-2xl border border-slate-100 p-3" key={item.id}>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-bold uppercase tracking-wide text-slate-400">{item.kind}</span>
                      {item.label === "Needs attention" ? (
                        <button
                          className="rounded-lg px-2 py-1 text-xs font-semibold text-amber-600 hover:bg-amber-50"
                          onClick={() => setSelectedThreatReport(item)}
                          type="button"
                        >
                          {item.label}
                        </button>
                      ) : (
                        <span className={`text-xs font-semibold ${item.error ? "text-red-600" : "text-emerald-600"}`}>{item.label}</span>
                      )}
                    </div>
                    <p className="mt-2 truncate text-sm font-medium text-slate-700" title={item.target}>{item.target}</p>
                  </li>
                ))}
              </ul>
            )}
          </aside>
        </div>
      </div>
      <ThreatReportModal report={selectedThreatReport} onClose={() => setSelectedThreatReport(null)} />
    </main>
  );
}

function AuthShell({ children, view, onViewChange }) {
  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="flex min-h-[calc(100vh-5rem)] w-full min-w-0 items-center justify-center">
        <section className="grid w-full max-w-6xl overflow-hidden rounded-3xl border border-white/10 bg-white shadow-2xl shadow-black/30 lg:min-h-[605px] lg:grid-cols-2">
          <div className="hidden bg-gradient-to-br from-indigo-600 via-violet-600 to-fuchsia-600 p-12 lg:flex lg:flex-col lg:justify-between">
            <div>
              <div className="mb-12 flex items-center gap-3 text-lg font-semibold">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-white/20">S</span>
                Secure Auth
              </div>
              <h1 className="max-w-sm text-4xl font-bold leading-tight">
                One secure place for your account.
              </h1>
              <p className="mt-5 max-w-sm text-indigo-100">
                Sign in to continue, or create an account in just a few steps.
              </p>
            </div>
            <p className="text-sm text-indigo-100/80">Protected access for your application.</p>
          </div>
          <div className="bg-white p-6 text-slate-900 sm:p-10 lg:p-14">
            <div className="mb-8 flex gap-5 border-b border-slate-200 text-sm font-medium">
              <Tab active={view === views.signIn} onClick={() => onViewChange(views.signIn)}>
                Sign in
              </Tab>
              <Tab active={view === views.signUp} onClick={() => onViewChange(views.signUp)}>
                Create account
              </Tab>
            </div>
            {children}
          </div>
        </section>
      </div>
    </main>
  );
}

function Tab({ active, children, onClick }) {
  return (
    <button
      className={`border-b-2 pb-3 transition ${
        active ? "border-indigo-600 text-indigo-600" : "border-transparent text-slate-500 hover:text-slate-800"
      }`}
      onClick={onClick}
      type="button"
    >
      {children}
    </button>
  );
}

function Field({ label, name, type = "text", autoComplete, value, onChange, required = true }) {
  const [visible, setVisible] = useState(false);
  const isPassword = type === "password";

  return (
    <label className="block text-sm font-medium text-slate-700">
      {label}
      <span className="relative mt-2 block">
        <input
          className="w-full rounded-xl border border-slate-200 px-4 py-3 pr-24 text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100"
          name={name}
          type={isPassword && visible ? "text" : type}
          autoComplete={autoComplete}
          value={value}
          onChange={onChange}
          required={required}
        />
        {isPassword && (
          <button
            className="absolute inset-y-0 right-3 my-auto h-8 px-2 text-sm font-medium text-indigo-600 hover:text-indigo-500"
            type="button"
            onClick={() => setVisible((current) => !current)}
            aria-pressed={visible}
            aria-label={`${visible ? "Hide" : "Show"} ${label.toLowerCase()}`}
          >
            {visible ? "Hide" : "Show"}
          </button>
        )}
      </span>
    </label>
  );
}

function Notice({ message, error }) {
  if (!message) return null;
  return (
    <p className={`rounded-xl px-4 py-3 text-sm ${error ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"}`} role="status">
      {message}
    </p>
  );
}

function SignIn({ onForgot, onSignedIn }) {
  const [form, setForm] = useState({ email: "", password: "" });
  const [state, setState] = useState({ busy: false, message: "", error: false });

  async function submit(event) {
    event.preventDefault();
    setState({ busy: true, message: "", error: false });
    try {
      const body = await request("/auth/login", { method: "POST", body: JSON.stringify(form) });
      setState({ busy: false, message: body.message || "Welcome back.", error: false });
      onSignedIn();
    } catch (error) {
      setState({ busy: false, message: error.message, error: true });
    }
  }

  return (
    <>
      <h2 className="text-3xl font-bold tracking-tight">Welcome back</h2>
      <p className="mt-2 text-slate-500">Sign in to access your account.</p>
      <form className="mt-8 space-y-5" onSubmit={submit}>
        <Field label="Email address" name="email" type="email" autoComplete="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} />
        <div>
          <Field label="Password" name="password" type="password" autoComplete="current-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
          <button className="mt-2 text-sm font-medium text-indigo-600 hover:text-indigo-500" onClick={onForgot} type="button">
            Forgot your password?
          </button>
        </div>
        <Notice {...state} />
        <button className="w-full rounded-xl bg-indigo-600 px-4 py-3 font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60" disabled={state.busy} type="submit">
          {state.busy ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </>
  );
}

function SignUp() {
  const [form, setForm] = useState({ display_name: "", email: "", password: "", confirmPassword: "" });
  const [state, setState] = useState({ busy: false, message: "", error: false });

  async function submit(event) {
    event.preventDefault();
    if (form.password !== form.confirmPassword) {
      setState({ busy: false, message: "Passwords do not match.", error: true });
      return;
    }
    setState({ busy: true, message: "", error: false });
    try {
      const body = await request("/auth/register", {
        method: "POST",
        body: JSON.stringify({ display_name: form.display_name, email: form.email, password: form.password })
      });
      setState({ busy: false, message: body.message || "Account created successfully.", error: false });
    } catch (error) {
      setState({ busy: false, message: error.message, error: true });
    }
  }

  const update = (name) => (event) => setForm({ ...form, [name]: event.target.value });
  return (
    <>
      <h2 className="text-3xl font-bold tracking-tight">Create an account</h2>
      <p className="mt-2 text-slate-500">Start with a secure account today.</p>
      <form className="mt-8 space-y-5" onSubmit={submit}>
        <Field label="Display name" name="display_name" autoComplete="name" value={form.display_name} onChange={update("display_name")} />
        <Field label="Email address" name="email" type="email" autoComplete="email" value={form.email} onChange={update("email")} />
        <Field label="Password" name="password" type="password" autoComplete="new-password" value={form.password} onChange={update("password")} />
        <Field label="Confirm password" name="confirmPassword" type="password" autoComplete="new-password" value={form.confirmPassword} onChange={update("confirmPassword")} />
        <Notice {...state} />
        <button className="w-full rounded-xl bg-indigo-600 px-4 py-3 font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60" disabled={state.busy} type="submit">
          {state.busy ? "Creating account..." : "Create account"}
        </button>
      </form>
    </>
  );
}

function ForgotPassword({ onBack }) {
  const [email, setEmail] = useState("");
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [requested, setRequested] = useState(false);
  const [state, setState] = useState({ busy: false, message: "", error: false });

  async function requestReset(event) {
    event.preventDefault();
    setState({ busy: true, message: "", error: false });
    try {
      const body = await request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
      setRequested(true);
      setState({ busy: false, message: body.message || "Check your email for reset instructions.", error: false });
    } catch (error) {
      setState({ busy: false, message: error.message, error: true });
    }
  }

  async function resetPassword(event) {
    event.preventDefault();
    if (newPassword !== confirmPassword) {
      setState({ busy: false, message: "Passwords do not match.", error: true });
      return;
    }
    setState({ busy: true, message: "", error: false });
    try {
      const body = await request("/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ email, token, new_password: newPassword })
      });
      setState({ busy: false, message: body.message || "Password reset successful.", error: false });
    } catch (error) {
      setState({ busy: false, message: error.message, error: true });
    }
  }

  return (
    <>
      <button className="mb-6 text-sm font-medium text-indigo-600 hover:text-indigo-500" onClick={onBack} type="button">&lt;- Back to sign in</button>
      <h2 className="text-3xl font-bold tracking-tight">Reset your password</h2>
      <p className="mt-2 text-slate-500">Request a reset instruction, then enter the token you receive.</p>
      <form className="mt-8 space-y-5" onSubmit={requestReset}>
        <Field label="Email address" name="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} />
        <button className="w-full rounded-xl border border-indigo-600 px-4 py-3 font-semibold text-indigo-600 transition hover:bg-indigo-50 disabled:opacity-60" disabled={state.busy} type="submit">
          {state.busy ? "Requesting..." : "Request reset"}
        </button>
      </form>
      <Notice {...state} />
      {requested && (
        <form className="mt-8 space-y-5 border-t border-slate-200 pt-8" onSubmit={resetPassword}>
          <Field label="Reset token / OTP" name="token" value={token} onChange={(event) => setToken(event.target.value)} />
          <Field label="New password" name="new_password" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
          <Field label="Confirm new password" name="confirm_new_password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} />
          <button className="w-full rounded-xl bg-indigo-600 px-4 py-3 font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-60" disabled={state.busy} type="submit">
            {state.busy ? "Resetting..." : "Reset password"}
          </button>
        </form>
      )}
    </>
  );
}

export default function App() {
  const [view, setView] = useState(views.signIn);
  if (view === views.dashboard) {
    return <Dashboard onSignOut={() => setView(views.signIn)} />;
  }
  return (
    <AuthShell view={view} onViewChange={setView}>
      {view === views.signIn && <SignIn onForgot={() => setView(views.forgot)} onSignedIn={() => setView(views.dashboard)} />}
      {view === views.signUp && <SignUp />}
      {view === views.forgot && <ForgotPassword onBack={() => setView(views.signIn)} />}
    </AuthShell>
  );
}
