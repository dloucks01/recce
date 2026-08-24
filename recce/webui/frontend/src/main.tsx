import React, { Component, ErrorInfo, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { CollabProvider } from "./collab";
import "./index.css";

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("React crash:", error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 40, fontFamily: "monospace", maxWidth: 800 }}>
          <h2 style={{ color: "#e55" }}>Page crashed</h2>
          <pre style={{ whiteSpace: "pre-wrap", color: "#ccc", background: "#1a1a2e", padding: 16, borderRadius: 8 }}>
            {this.state.error.message}{"\n"}{this.state.error.stack}
          </pre>
          <button onClick={() => { this.setState({ error: null }); window.location.reload(); }}
                  style={{ marginTop: 16, padding: "8px 16px", cursor: "pointer" }}>
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <CollabProvider>
        <App />
      </CollabProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
