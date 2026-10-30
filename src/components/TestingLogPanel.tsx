import type { Dispatch, SetStateAction } from "react";
import { ClipboardCopy, CheckCircle2, Trash2, XCircle } from "lucide-react";

export type LogKind = "info" | "ok" | "fail" | "sys";
export type LogEntry = { text: string; kind: LogKind };

/// Тёмная панель «Результаты тестирования» — общая для вкладок
/// «Профили обхода» и «Починка сайтов». Сам стейт лога живёт в App,
/// поэтому содержимое переживает переключение вкладок.
export default function TestingLogPanel({ log, setLog }: {
  log: LogEntry[];
  setLog: Dispatch<SetStateAction<LogEntry[]>>;
}) {
  const appendEntry = (text: string) =>
    setLog((prev) => [...prev, { text, kind: "info" as LogKind }].slice(-100));

  const copyLogs = () => {
    if (log.length === 0) return;
    navigator.clipboard.writeText(log.map((l) => l.text).join("\n")).then(
      () => appendEntry("[Лог] Скопировано в буфер обмена."),
      () => appendEntry("[Лог] Не удалось скопировать в буфер обмена.")
    );
  };

  // Полная очистка панели: пустой массив заменяет весь стейт лога.
  const clearLogs = () => setLog([]);

  return (
    <div className="flex-1 bg-gray-900 rounded-xl p-4 flex flex-col min-h-[300px]">
      <div className="flex items-center justify-between mb-2 border-b border-gray-700 pb-2">
        <span className="text-gray-400 text-sm font-semibold">Результаты тестирования</span>
        <div className="flex items-center gap-2">
          <button
            onClick={copyLogs}
            disabled={log.length === 0}
            className="flex items-center gap-1 bg-gray-700 hover:bg-gray-800 disabled:bg-gray-500 text-white px-3 py-1 rounded text-xs font-bold transition"
            title="Скопировать все логи в буфер обмена"
          >
            <ClipboardCopy size={14} /> Копировать логи
          </button>
          <button
            onClick={clearLogs}
            disabled={log.length === 0}
            className="flex items-center gap-1 bg-gray-700 hover:bg-red-700 disabled:bg-gray-500 text-white px-3 py-1 rounded text-xs font-bold transition"
            title="Очистить все логи этой панели"
          >
            <Trash2 size={14} /> Очистить логи
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto font-mono text-sm break-all space-y-1 whitespace-pre-wrap">
        {log.length === 0 ? (
          <span className="text-gray-600">Ожидание...</span>
        ) : (
          log.map((l, i) => {
            if (l.kind === "ok") {
              return (
                <div key={i} className="flex items-start gap-1.5 text-green-400">
                  <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
                  <span>{l.text}</span>
                </div>
              );
            }
            if (l.kind === "fail") {
              return (
                <div key={i} className="flex items-start gap-1.5 text-red-400">
                  <XCircle size={15} className="mt-0.5 shrink-0" />
                  <span>{l.text}</span>
                </div>
              );
            }
            return (
              <div key={i} className={l.kind === "sys" ? "text-gray-500" : "text-blue-300"}>
                {l.text}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
