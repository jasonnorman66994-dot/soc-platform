"use client";

function severityColor(severity) {
  if (severity === "critical") return "#ef4444";
  if (severity === "high") return "#f97316";
  if (severity === "medium") return "#eab308";
  return "#22c55e";
}

export default function AlertFeed({ records }) {
  return (
    <section style={panel}>
      <h2 style={title}>Live Alerts</h2>
      <div style={listWrap}>
        {records.length === 0 ? <p style={empty}>No streamed alerts yet.</p> : null}
        {records.map((record, idx) => {
          const alerts = Array.isArray(record.alerts) ? record.alerts : [];
          return (
            <article key={`${record.timestamp || "t"}-${idx}`} style={item}>
              <header style={itemHeader}>
                <strong>{record.event?.event_type || "event"}</strong>
                <span style={meta}>{record.event?.user || "unknown user"}</span>
              </header>
              <div style={chips}>
                {alerts.map((alert, i) => (
                  <span
                    key={`${alert.type || "alert"}-${i}`}
                    style={{ ...chip, borderColor: severityColor(alert.severity), color: severityColor(alert.severity) }}
                  >
                    {(alert.type || "alert").replaceAll("_", " ")}
                  </span>
                ))}
              </div>
              <p style={meta}>IP: {record.event?.ip || "n/a"} | Location: {record.event?.location || "n/a"}</p>
            </article>
          );
        })}
      </div>
    </section>
  );
}

const panel = {
  background: "rgba(15, 23, 42, 0.78)",
  border: "1px solid rgba(56, 189, 248, 0.35)",
  borderRadius: 16,
  padding: 14,
  minHeight: 360,
};

const title = { marginTop: 0, marginBottom: 10, fontFamily: "Space Grotesk, Sora, sans-serif" };
const listWrap = { display: "grid", gap: 10, maxHeight: 520, overflowY: "auto", paddingRight: 4 };
const empty = { margin: 0, color: "#94a3b8" };
const item = {
  background: "rgba(2, 6, 23, 0.8)",
  border: "1px solid rgba(148, 163, 184, 0.25)",
  borderRadius: 12,
  padding: 10,
};
const itemHeader = { display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" };
const meta = { margin: "6px 0 0", color: "#94a3b8", fontSize: 12 };
const chips = { display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 };
const chip = {
  border: "1px solid",
  borderRadius: 999,
  padding: "3px 8px",
  fontSize: 12,
  textTransform: "capitalize",
};
