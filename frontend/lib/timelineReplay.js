export async function replayTimeline(events, emit, delayMs = 1200) {
  const safeDelay = Math.max(200, Number.isFinite(delayMs) ? delayMs : 1200);
  for (let i = 0; i < events.length; i += 1) {
    emit(events[i], i);
    await new Promise((resolve) => setTimeout(resolve, safeDelay));
  }
}
