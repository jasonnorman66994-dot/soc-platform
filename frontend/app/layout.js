export const metadata = {
  title: "Nexus SOC Platform",
  description: "Multi-tenant SIEM + SOAR + AI analyst platform",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "Space Grotesk, Sora, Segoe UI, sans-serif", background: "#050913", color: "#e2e8f0" }}>
        {children}
      </body>
    </html>
  );
}
