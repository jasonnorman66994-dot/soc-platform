export function connectSocSocket({
  url,
  onMessage,
  onStateChange,
  reconnectDelayMs = 1500,
}) {
  let socket;
  let reconnectTimer;
  let closedManually = false;

  function connect() {
    onStateChange?.("connecting");
    socket = new WebSocket(url);

    socket.onopen = () => onStateChange?.("connected");

    socket.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        onMessage?.(parsed);
      } catch {
        onMessage?.(event.data);
      }
    };

    socket.onclose = () => {
      onStateChange?.("disconnected");
      if (!closedManually) {
        reconnectTimer = setTimeout(connect, reconnectDelayMs);
      }
    };

    socket.onerror = () => {
      onStateChange?.("error");
    };
  }

  connect();

  return () => {
    closedManually = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
    }
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.close();
    }
  };
}
