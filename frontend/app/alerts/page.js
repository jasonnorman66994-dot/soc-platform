"use client";

import { useEffect, useState } from "react";
import AlertFeed from "../../components/AlertFeed";
import { connectSocSocket } from "../../lib/socket";

const SOC_WS = process.env.NEXT_PUBLIC_SOC_CORE_WS_URL || "ws://localhost:8000/ws/alerts";

export default function AlertsPage() {
  const [records, setRecords] = useState([]);

  useEffect(() => {
    const disconnect = connectSocSocket({
      url: SOC_WS,
      onMessage: (payload) => setRecords((current) => [payload, ...current].slice(0, 80)),
    });
    return disconnect;
  }, []);

  return <main style={{ padding: 20 }}><AlertFeed records={records} /></main>;
}
