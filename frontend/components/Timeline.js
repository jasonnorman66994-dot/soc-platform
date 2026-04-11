"use client";

export default function Timeline({ events, replayIndex }) {
  return (
    <section style={panel}>
      <h2 style={title}>Attack Timeline</h2>
      <div style={track}>
        {events.length === 0 ? <p style={empty}>No timeline events yet.</p> : null}
        {events.map((event, index) => {
          const active = replayIndex === index;
          return (
            <div key={`${event.timestamp || "time"}-${index}`} style={row}>
              <div style={{ ...dot, background: active ? "#f97316" : "#38bdf8" }} />
              <div style={{ ...card, borderColor: active ? "#f97316" : "rgba(148, 163, 184, 0.2)" }}>
                <p style={eventTitle}>{event.event_type || "event"}</p>
                <p style={meta}>{event.timestamp || "unknown time"}</p>
                <p style={meta}>{event.user || "unknown user"} | {event.ip || "n/a"}</p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

const panel = {
  background: "rgba(15, 23, 42, 0.78)",
  border: "1px solid rgba(59, 130, 246, 0.35)",
  borderRadius: 16,
  padding: 14,
};
const title = { marginTop: 0, marginBottom: 10, fontFamily: "Space Grotesk, Sora, sans-serif" };
const track = { display: "grid", gap: 8, maxHeight: 420, overflowY: "auto", paddingRight: 4 };
const row = { display: "grid", gridTemplateColumns: "12px 1fr", gap: 10, alignItems: "start" };
const dot = { width: 10, height: 10, borderRadius: "50%", marginTop: 10 };
const card = {
  border: "1px solid",
  borderRadius: 12,
  padding: 10,
  background: "rgba(2, 6, 23, 0.7)",
};
const eventTitle = { margin: 0, fontWeight: 700 };
const meta = { margin: "6px 0 0", color: "#94a3b8", fontSize: 12 };
const empty = { margin: 0, color: "#94a3b8" };
