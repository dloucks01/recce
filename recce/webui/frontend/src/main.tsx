import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { CollabProvider } from "./collab";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <CollabProvider>
      <App />
    </CollabProvider>
  </React.StrictMode>
);
