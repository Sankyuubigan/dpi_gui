import { logFront, logFrontendEvent } from "@my-tauri-plugins/plugin-logs";

/// Уровни строк фронт-лога: мапятся на тег `[LEVEL]` в строке плагина
/// `[ts] [LEVEL] msg`; раскраска LogsPanel — по тегу (FAIL/ERROR красный,
/// WARN янтарный, остальное — зелёный mono).
export type LogKind = "info" | "ok" | "fail" | "warn" | "sys";

/// Аппендеры единого лог-конвейера (08.11.26): строки уходят через плагин
/// logs в общий файл и событие logs:message → панель на всех вкладках.
/// Прежний локальный стейт (setLog) и дубль-слушатель события "log" удалены:
/// бэкенд-строки приходят в панель одним каналом (подписка в App.tsx).
export function useTestingLog() {
  const appendEntry = (text: string, kind: LogKind) => {
    logFrontendEvent(kind.toUpperCase(), text);
  };
  const appendLog = (msg: string) => {
    logFront(msg);
  };
  return { appendEntry, appendLog };
}
