"use client";

import { useEffect, useState } from "react";
import AlertFeed from "../../components/AlertFeed";
import { connectSocSocket } from "../../lib/socket";

function resolveSocWsUrl() {
  if (process.env.NEXT_PUBLIC_SOC_CORE_WS_URL) {
    return process.env.NEXT_PUBLIC_SOC_CORE_WS_URL;
  }
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    return `${protocol}://${window.location.host}/ws/alerts`;
  }
  return "ws://localhost:8000/ws/alerts";
}

export default function AlertsPage() {
  const [records, setRecords] = useState([]);

  useEffect(() => {
    const disconnect = connectSocSocket({
      url: resolveSocWsUrl(),
      onMessage: (payload) => setRecords((current) => [payload, ...current].slice(0, 80)),
    });
    return disconnect;
  }, []);

  return <main style={{ padding: 20 }}><AlertFeed records={records} /></main>;
}
