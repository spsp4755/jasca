import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "pretendard/dist/web/variable/pretendardvariable-dynamic-subset.css";
import App from "./App";
import { applySavedTheme } from "./lib/theme";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/components.css";

// CSP forbids inline scripts, so the saved theme is applied here, before the first render.
applySavedTheme();
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
