import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { initFrontendLogging } from "./lib/frontendLogger";
import { syncInitialLang } from "./store/settingsStore";

initFrontendLogging();
void syncInitialLang();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
