import { useEffect, type Dispatch, type SetStateAction } from "react";
import { listen } from "@tauri-apps/api/event";
import type { LogEntry, LogKind } from "./TestingLogPanel";

/// Аппендеры тестового лога + подписка на системные события бэкенда.
/// Общие для вкладок «Профили обхода» и «Починка сайтов»; сам лог живёт
/// в App и не сбрасывается при смене вкладок (PRP §7.1).
export function useTestingLog(setLog: Dispatch<SetStateAction<LogEntry[]>>) {
  const appendEntry = (text: string, kind: LogKind) => {
    setLog((prev) => [...prev, { text, kind }].slice(-100));
  };
  const appendLog = (msg: string) => appendEntry(msg, "info");

  useEffect(() => {
    const unlisten = listen<string>("log", (event) => {
      appendEntry(`[СИСТЕМА] ${event.payload}`, "sys");
    });
    return () => {
      unlisten.then(f => f());
    };
  }, []);

  return { appendEntry, appendLog };
}
