"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

export default function HomePage() {
  const [lead, setLead] = useState({ company: "", email: "", role: "security_lead" });
  const [leadState, setLeadState] = useState("idle");
  const [leadMessage, setLeadMessage] = useState("");

  async function trackEvent(eventName, meta = {}) {
    try {
      await fetch("/api/public/analytics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_name: eventName, page: "/", meta }),
      });
    } catch {
      // Do not interrupt UX for analytics errors.
    }
  }

  useEffect(() => {
    trackEvent("landing_view", { section: "hero" });
  }, []);
  async function submitLead(e) {
    e.preventDefault();
    setLeadState("loading");
    setLeadMessage("");
    try {
      const res = await fetch("/api/public/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...lead, source: "landing" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail || "Could not capture lead");
      setLeadState("success");
      trackEvent("lead_submitted", { source: "landing" });
      setLeadMessage("Thanks. Your team is now on the launch list.");
      setLead({ company: "", email: "", role: "security_lead" });
    } catch (err) {
      setLeadState("error");
      setLeadMessage(err.message || "Submission failed");
    }
  }

  return (
    <main style={page}>
      <div style={glowA} />
      <div style={glowB} />

      <header style={header}>
        <div style={logo}>NEXUS SOC</div>
        <nav style={nav}>
          <a href="#platform" style={navLink}>Platform</a>
          <a href="#pricing" style={navLink} onClick={() => trackEvent("pricing_section_click", { location: "nav" })}>Pricing</a>
          <a href="#proof" style={navLink}>Proof</a>
          <Link href="/command-center" style={ctaGhost} onClick={() => trackEvent("cta_live_demo_click", { location: "nav" })}>Live Demo</Link>
        </nav>
      </header>

      <section style={hero}>
        <p style={eyebrow}>Multi-Tenant SIEM + SOAR + AI Analyst</p>
        <h1 style={headline}>Stop Breaches in Minutes, Not Meetings.</h1>
        <p style={subline}>
          Enterprise-ready SOC platform with tenant isolation, API-key ingestion, detection marketplace,
          executive metrics, and automated response orchestration built in.
        </p>
        <div style={heroActions}>
          <Link href="/command-center" style={ctaPrimary} onClick={() => trackEvent("cta_open_command_center", { location: "hero" })}>Open Command Center</Link>
          <Link href="/soc-dashboard" style={ctaSecondary} onClick={() => trackEvent("cta_open_soc_dashboard", { location: "hero" })}>Open SOC Dashboard</Link>
          <a href="/api/demo/bootstrap" style={ctaSecondary} onClick={() => trackEvent("cta_bootstrap_click", { location: "hero" })}>View Demo Tenant Bootstrap</a>
        </div>
      </section>

      <section id="proof" style={proofGrid}>
        <article style={proofCard}><h3 style={cardTitle}>SOC2-Ready Audit Trail</h3><p style={cardText}>Every privileged action is tracked with tenant, user, resource, and timestamp.</p></article>
        <article style={proofCard}><h3 style={cardTitle}>Production RBAC</h3><p style={cardText}>Owner, admin, analyst, viewer roles with explicit enforcement by action.</p></article>
        <article style={proofCard}><h3 style={cardTitle}>Detection Marketplace</h3><p style={cardText}>Rule packs from Microsoft, phishing, and insider threat categories out of the box.</p></article>
      </section>

      <section id="platform" style={platform}>
        <h2 style={sectionTitle}>Why Buyers Choose This Platform</h2>
        <div style={featureRows}>
          <div style={feature}><strong>Tenant Isolation:</strong> Query-level tenant boundaries across events, alerts, incidents, users, and keys.</div>
          <div style={feature}><strong>Executive Visibility:</strong> MTTD, MTTR, risk trends, and incident volume in one board view.</div>
          <div style={feature}><strong>Realistic Simulation:</strong> Email -&gt; click -&gt; geo anomaly -&gt; exfil chain to demo real threat handling.</div>
          <div style={feature}><strong>Deploy Anywhere:</strong> FastAPI + Next.js + PostgreSQL + Redis under Docker Compose.</div>
        </div>
      </section>

      <section id="pricing" style={pricing}>
        <h2 style={sectionTitle}>Simple, Defensible Pricing</h2>
        <div style={pricingGrid}>
          <article style={priceCard}><h3>Free</h3><p style={price}>$0</p><p>Single workspace exploration, core incident views, no advanced marketplace detections.</p></article>
          <article style={{ ...priceCard, border: "1px solid #f97316" }}><h3>Pro</h3><p style={price}>$2,500/mo</p><p>Full detection packs, response actions, dashboard metrics, and API-key ingestion.</p></article>
          <article style={priceCard}><h3>Enterprise</h3><p style={price}>Custom</p><p>Dedicated support, private deployment, compliance exports, custom pack development.</p></article>
        </div>
      </section>

      <section style={captureSection}>
        <h2 style={sectionTitle}>Join the Early Access Program</h2>
        <p style={{ color: "#cbd5e1", marginTop: 4 }}>Get onboarding priority, direct founder support, and roadmap influence.</p>
        <form onSubmit={submitLead} style={captureForm}>
          <input
            style={input}
            placeholder="Company"
            value={lead.company}
            onChange={(e) => setLead((s) => ({ ...s, company: e.target.value }))}
            required
          />
          <input
            style={input}
            type="email"
            placeholder="Work email"
            value={lead.email}
            onChange={(e) => setLead((s) => ({ ...s, email: e.target.value }))}
            required
          />
          <input
            style={input}
            placeholder="Role (e.g. CISO)"
            value={lead.role}
            onChange={(e) => setLead((s) => ({ ...s, role: e.target.value }))}
            required
          />
          <button style={captureBtn} type="submit" disabled={leadState === "loading"}>
            {leadState === "loading" ? "Submitting..." : "Request Access"}
          </button>
        </form>
        {leadMessage ? <p style={{ marginBottom: 0, color: leadState === "success" ? "#22c55e" : "#f87171" }}>{leadMessage}</p> : null}
      </section>

      <footer style={footer}>
        <p style={{ margin: 0 }}>Built for SOC leaders, product engineers, and security founders.</p>
        <p style={{ margin: 0 }}><a href="/api/docs" style={navLink}>API Docs</a> | <a href="/api/health" style={navLink}>Health</a></p>
      </footer>
    </main>
  );
}

const page = {
  minHeight: "100vh",
  color: "#ecfeff",
  background: "radial-gradient(circle at 20% 10%, #1d4ed8 0%, #0f172a 35%, #020617 100%)",
  position: "relative",
  overflow: "hidden",
  padding: "20px clamp(18px, 4vw, 54px) 36px",
};

const glowA = {
  position: "absolute",
  top: -130,
  left: -90,
  width: 300,
  height: 300,
  borderRadius: "50%",
  background: "rgba(14, 165, 233, 0.25)",
  filter: "blur(40px)",
};

const glowB = {
  position: "absolute",
  right: -70,
  top: 130,
  width: 260,
  height: 260,
  borderRadius: "50%",
  background: "rgba(249, 115, 22, 0.2)",
  filter: "blur(40px)",
};

const header = {
  position: "relative",
  zIndex: 2,
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: 12,
  flexWrap: "wrap",
};

const logo = {
  fontFamily: "Space Grotesk, Sora, ui-sans-serif",
  fontWeight: 800,
  letterSpacing: "0.08em",
};

const nav = {
  display: "flex",
  gap: 16,
  alignItems: "center",
  flexWrap: "wrap",
};

const navLink = {
  color: "#cbd5e1",
  textDecoration: "none",
  fontSize: 14,
};

const ctaGhost = {
  color: "#e2e8f0",
  textDecoration: "none",
  border: "1px solid rgba(148, 163, 184, 0.5)",
  padding: "8px 10px",
  borderRadius: 999,
  fontSize: 14,
};

const hero = {
  position: "relative",
  zIndex: 2,
  maxWidth: 800,
  marginTop: 54,
};

const eyebrow = {
  color: "#7dd3fc",
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  fontSize: 12,
  marginBottom: 8,
};

const headline = {
  margin: 0,
  fontFamily: "Space Grotesk, Sora, ui-sans-serif",
  fontSize: "clamp(2rem, 6vw, 4.4rem)",
  lineHeight: 1.04,
};

const subline = {
  color: "#cbd5e1",
  marginTop: 16,
  maxWidth: 720,
  lineHeight: 1.6,
};

const heroActions = {
  display: "flex",
  flexWrap: "wrap",
  gap: 12,
  marginTop: 24,
};

const ctaPrimary = {
  background: "linear-gradient(135deg, #f97316, #fb7185)",
  color: "white",
  borderRadius: 999,
  textDecoration: "none",
  padding: "12px 18px",
  fontWeight: 700,
};

const ctaSecondary = {
  background: "rgba(15, 23, 42, 0.6)",
  color: "#f1f5f9",
  border: "1px solid rgba(148, 163, 184, 0.4)",
  borderRadius: 999,
  textDecoration: "none",
  padding: "12px 18px",
  fontWeight: 700,
};

const proofGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
  gap: 12,
  marginTop: 38,
  position: "relative",
  zIndex: 2,
};

const proofCard = {
  background: "rgba(2, 6, 23, 0.7)",
  border: "1px solid rgba(148, 163, 184, 0.25)",
  borderRadius: 14,
  padding: 14,
};

const cardTitle = { marginTop: 0, marginBottom: 8 };
const cardText = { margin: 0, color: "#cbd5e1", lineHeight: 1.45 };

const platform = { marginTop: 40, position: "relative", zIndex: 2 };
const sectionTitle = { marginTop: 0, marginBottom: 10, fontFamily: "Space Grotesk, Sora, ui-sans-serif" };

const featureRows = { display: "grid", gap: 8 };
const feature = {
  background: "rgba(15, 23, 42, 0.66)",
  border: "1px solid rgba(148, 163, 184, 0.2)",
  borderRadius: 10,
  padding: 12,
  color: "#e2e8f0",
};

const pricing = { marginTop: 40, position: "relative", zIndex: 2 };
const pricingGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))",
  gap: 12,
};

const priceCard = {
  background: "rgba(15, 23, 42, 0.66)",
  border: "1px solid rgba(148, 163, 184, 0.22)",
  borderRadius: 12,
  padding: 14,
};

const price = { fontSize: 24, marginTop: 0, marginBottom: 10, color: "#f8fafc" };

const footer = {
  marginTop: 32,
  borderTop: "1px solid rgba(148, 163, 184, 0.2)",
  paddingTop: 14,
  display: "grid",
  gap: 8,
  position: "relative",
  zIndex: 2,
};

const captureSection = {
  marginTop: 38,
  position: "relative",
  zIndex: 2,
  background: "rgba(2, 6, 23, 0.72)",
  border: "1px solid rgba(148, 163, 184, 0.25)",
  borderRadius: 16,
  padding: 16,
};

const captureForm = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 10,
  marginTop: 10,
};

const input = {
  background: "#0b1220",
  color: "#e2e8f0",
  border: "1px solid #334155",
  borderRadius: 10,
  padding: "10px 12px",
};

const captureBtn = {
  background: "linear-gradient(135deg, #0891b2, #2563eb)",
  color: "white",
  border: "none",
  borderRadius: 10,
  padding: "10px 12px",
  fontWeight: 700,
  cursor: "pointer",
};
