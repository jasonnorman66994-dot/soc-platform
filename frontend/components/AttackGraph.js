"use client";

import ReactFlow, { Background, Controls, MiniMap } from "reactflow";
import "reactflow/dist/style.css";

export default function AttackGraph({ nodes, edges, onNodeClick }) {
  return (
    <section style={panel}>
      <h2 style={title}>Investigation Graph</h2>
      <div style={graph_wrap}>
        <ReactFlow fitView nodes={nodes} edges={edges} onNodeClick={onNodeClick}>
          <Background gap={18} color="#1e293b" />
          <MiniMap pannable />
          <Controls />
        </ReactFlow>
      </div>
    </section>
  );
}

const panel = {
  background: "rgba(15, 23, 42, 0.78)",
  border: "1px solid rgba(14, 165, 233, 0.35)",
  borderRadius: 16,
  padding: 14,
};

const title = { marginTop: 0, marginBottom: 10, fontFamily: "Space Grotesk, Sora, sans-serif" };

const graph_wrap = {
  width: "100%",
  height: 430,
  borderRadius: 12,
  overflow: "hidden",
  border: "1px solid rgba(148, 163, 184, 0.25)",
};
