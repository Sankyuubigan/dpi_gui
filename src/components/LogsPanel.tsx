import { useEffect, useRef, useState } from "react";
import { logFront, saveLogsToFile } from "@my-tauri-plugins/plugin-logs";
import { Activity, ClipboardCopy, Save, Eraser } from "lucide-react";

/// ЕДИНАЯ лог-область приложения (08.11.26): один источник данных —
/// строки единого конвейера плагина logs (log::info! бэкенда + logFront
/// фронта), один стейт в App, этот компонент рендерится на ВСЕХ вкладках.
/// Полная история сессии — вкладка «Логи» (тот же компонент в full-режиме).
///
/// Раскраска — только по тегу уровня в строке плагина `[ts] [LEVEL] msg`
/// (FAIL/ERROR красный, WARN янтарный, база — зелёный mono как в старом
/// «Логе событий» вкладки «Управление»), никакой семантики текста.
export default function LogsPanel({ lines, onClear, full = false }: {
  lines: string[];
  /// Очистить панель (только UI-стейт; файл лога плагин не трогает).
  onClear: () => void;
  /// full — вкладка «Логи»: на всю высоту + переключатель автоскролла.
  full?: boolean;
}) {
  const [autoscroll, setAutoscroll] = useState(true);
  const endRef = useRef<HTMLDivElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoscroll) endRef.current?.scrollIntoView({ behavior: "auto" });
  }, [lines, autoscroll]);

  const copyAll = () => {
    navigator.clipboard.writeText(lines.join("\n"))
      .then(() => logFront("[Логи] Скопировано в буфер: строк — " + lines.length))
      .catch(() => logFront("[Логи] ОШИБКА: не удалось скопировать лог в буфер."));
  };

  const saveToFile = () => {
    saveLogsToFile(lines.join("\n"))
      .then((path) => logFront(path
        ? `[Логи] Сохранено: ${path}`
        : "[Логи] Сохранение отменено."))
      .catch((e) => logFront(`[Логи] ОШИБКА сохранения: ${e}`));
  };

  const lineClass = (l: string) => {
    if (l.includes("[FAIL]") || l.includes("[ERROR]")) return "text-red-400";
    if (l.includes("[WARN]")) return "text-amber-300";
    return "text-green-400";
  };

  return (
    <div className={full
      ? "flex-1 bg-gray-900 rounded-xl p-4 flex flex-col min-h-0"
      : "bg-gray-900 rounded-xl p-4 flex flex-col h-[220px]"}>
      <div className="flex items-center gap-2 text-gray-400 mb-2 border-b border-gray-700 pb-2 flex-wrap">
        <Activity size={16} />
        <span className="text-sm font-semibold">{full ? "Логи — полная история сессии" : "Лог событий"}</span>
        <span className="text-xs text-gray-500">строк: {lines.length}</span>
        <div className="ml-auto flex items-center gap-1">
          {full && (
            <label className="flex items-center gap-1 text-xs text-gray-400 mr-1 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoscroll}
                onChange={(e) => setAutoscroll(e.target.checked)}
                className="accent-blue-500"
              />
              автоскролл
            </label>
          )}
          <button
            onClick={copyAll}
            className="flex items-center gap-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700"
            title="Скопировать весь лог в буфер обмена"
          >
            <ClipboardCopy size={13} /> Копировать
          </button>
          <button
            onClick={saveToFile}
            className="flex items-center gap-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700"
            title="Сохранить лог в текстовый файл (диалог «Сохранить как»)"
          >
            <Save size={13} /> Сохранить
          </button>
          <button
            onClick={onClear}
            className="flex items-center gap-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-700"
            title="Очистить панель (только на экране; файл лога не трогается)"
          >
            <Eraser size={13} /> Очистить
          </button>
        </div>
      </div>
      <div ref={boxRef} className="flex-1 overflow-y-auto font-mono text-sm break-all space-y-1">
        {lines.length === 0 ? <span className="text-gray-600">Ожидание действий...</span> : null}
        {lines.map((l, i) => <div key={i} className={lineClass(l)}>{l}</div>)}
        <div ref={endRef} />
      </div>
    </div>
  );
}
