"use client";

import { useEffect, useState } from "react";
import Timeline from "../../components/Timeline";

const SOC_API = process.env.NEXT_PUBLIC_SOC_CORE_API_URL || "http://localhost:8000";

export default function TimelinePage() {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    async function load() {
      const res = await fetch(`${SOC_API}/events?limit=80`);
      const data = await res.json();
      setEvents(Array.isArray(data) ? data : []);
    }
    load();
  }, []);

  return <main style={{ padding: 20 }}><Timeline events={events} replayIndex={-1} /></main>;
}
