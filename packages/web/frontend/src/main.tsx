import "./styles/index.css";
import "./i18n";
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { installVersionCheck } from "./versionCheck";

// 部署更新检测：切回标签页时若服务端 entry hash 已变（up.sh --build 后）自动 reload，
// 消灭「旧标签页一直跑旧 bundle」。dev 模式自动禁用。
installVersionCheck();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
