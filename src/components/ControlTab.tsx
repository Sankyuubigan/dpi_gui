import { useState, useEffect, useRef, type Dispatch, type SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Play, Square, Activity, Eye, Terminal, Trash2, Search } from "lucide-react";
import { reasonToHuman } from "./reasonText";
import type { Suspicion } from "../App";

export default function ControlTab({
  isRunning,
  profiles,
  config,
  saveConfig,
  logs,
  suspicions,
  setSuspicions,
  logMsg,
  onFixDomain,
}: {
  isRunning: boolean;
  profiles: any[];
  config: any;
  saveConfig: (c: any) => void;
  logs: string[];
  suspicions: Suspicion[];
  setSuspicions: Dispatch<SetStateAction<Suspicion[]>>;
  logMsg: (msg: string) => void;
  /// Перенести домен на вкладку «Починка сайтов» (подстановка в поле анализа).
  onFixDomain: (domain: string) => void;
}) {
  const logEndRef = useRef<HTMLDivElement>(null);
  // Выбранная позиция в списке ошибок (домен). null = ничего не выбрано.
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "auto" });
  }, [logs]);

  // PRP §7.1: храним до 5000 строк в App, рендерим последние ~500 для скорости.
  const visibleLogs = logs.slice(-500);

  // Очистка ТОЛЬКО выбранной позиции: удаляем её из списка ошибок, остальные
  // остаются. Если с того же домена снова придут ошибки — детектор добавит
  // строку заново (дедап в App), это ожидаемое поведение.
  const clearSelected = () => {
    if (!selectedDomain) return;
    const cleared = selectedDomain;
    setSuspicions(prev => prev.filter(s => s.domain !== cleared));
    logMsg(`Ошибки сети: очищена позиция ${cleared}`);
    setSelectedDomain(null);
  };

  // «Анализ»: отправить выбранный домен на вкладку «Починка сайтов» —
  // он подставится в поле анализа, юзер запускает «Анализ сайта / IP» сам.
  const sendDomainToFix = () => {
    if (!selectedDomain) return;
    const domain = selectedDomain;
    logMsg(`Ошибки сети: домен ${domain} отправлен на вкладку «Починка сайтов»`);
    onFixDomain(domain);
  };

  const handleStart = async () => {
    if (!config.selected_profile) {
      logMsg("ОШИБКА: Выберите профиль обхода!");
      return;
    }
    try {
      logMsg("Запуск службы...");
      const result: string = await invoke("start_bypass", {
        profileName: config.selected_profile,
        gameFilter: config.game_filter
      });
      logMsg(result);
    } catch (e: any) {
      logMsg(`Ошибка запуска: ${e}`);
    }
  };

  const handleStop = async () => {
    try {
      logMsg("Остановка процессов...");
      const result: string = await invoke("stop_bypass");
      logMsg(result);
      logMsg("Статус: ОСТАНОВЛЕНО");
    } catch (e: any) {
      logMsg(`Ошибка остановки: ${e}`);
    }
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-800">Статус работы</h2>
          <div className="flex items-center gap-2 mt-2">
            <div className={`w-3 h-3 rounded-full ${isRunning ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className={`font-semibold ${isRunning ? 'text-green-600' : 'text-red-600'}`}>
              {isRunning ? 'ПРОЦЕСС АКТИВЕН' : 'ОСТАНОВЛЕНО'}
            </span>
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleStart}
            disabled={isRunning}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white px-6 py-3 rounded-lg font-bold transition-colors"
          >
            <Play size={20} /> ЗАПУСТИТЬ
          </button>
          <button
            onClick={handleStop}
            className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg font-bold transition-colors"
          >
            <Square size={20} /> ОСТАНОВИТЬ
          </button>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 className="font-bold mb-4">Настройки запуска</h3>
        <div className="flex flex-col gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Единый профиль обхода (для всех списков)</label>
            <select
              value={config.selected_profile || ""}
              onChange={(e) => saveConfig({...config, selected_profile: e.target.value})}
              className="w-full border-gray-300 rounded-md shadow-sm p-2 border focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="" disabled>-- Выберите профиль --</option>
              {profiles.map((p: any) => (
                <option key={p.name} value={p.name}>{p.name}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="gameFilter"
              checked={config.game_filter || false}
              onChange={(e) => saveConfig({...config, game_filter: e.target.checked})}
              className="w-4 h-4 text-blue-600 rounded border-gray-300"
            />
            <label htmlFor="gameFilter" className="text-gray-700">Включить игровой фильтр портов (1024-65535)</label>
          </div>
        </div>
      </div>

      {/* СПИСОК ОШИБОК СЕТИ: строка на домен, дедуп по домену, повтор
          обновляет счётчик/время строке. Клик по строке — выбор позиции;
          «Анализ» переносит выбранный домен на вкладку «Починка сайтов»,
          «Очистить» удаляет ТОЛЬКО выбранную. Повторные ошибки
          того же домена снова появятся в списке — это норма. */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <Eye size={18} className="text-red-500" />
            <h3 className="font-bold text-gray-800">Ошибки сети ({suspicions.length})</h3>
          </div>
          {suspicions.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={sendDomainToFix}
                disabled={!selectedDomain}
                className={
                  "flex items-center gap-2 px-4 py-2 rounded-md font-bold text-sm transition-colors border " +
                  (selectedDomain
                    ? "border-purple-300 text-purple-600 hover:bg-purple-50"
                    : "border-gray-200 text-gray-400 cursor-not-allowed")
                }
                title={
                  selectedDomain
                    ? `Перенести домен на вкладку «Починка сайтов» для анализа: ${selectedDomain}`
                    : "Сначала выберите позицию — кликните на строку списка"
                }
              >
                <Search size={16} /> Анализ
              </button>
              <button
                onClick={clearSelected}
                disabled={!selectedDomain}
                className={
                  "flex items-center gap-2 px-4 py-2 rounded-md font-bold text-sm transition-colors border " +
                  (selectedDomain
                    ? "border-red-300 text-red-600 hover:bg-red-50"
                    : "border-gray-200 text-gray-400 cursor-not-allowed")
                }
                title={
                  selectedDomain
                    ? `Удалить выбранную позицию из списка: ${selectedDomain}`
                    : "Сначала выберите позицию — кликните на строку списка"
                }
              >
                <Trash2 size={16} /> Очистить
              </button>
            </div>
          )}
        </div>
        {suspicions.length === 0 ? (
          <p className="text-sm text-gray-500">
            Пока ошибок сети не замечено. Список наполняется фоновым
            детектором, когда обход активен.
          </p>
        ) : (
          <div className="max-h-48 overflow-y-auto divide-y divide-gray-100">
            {suspicions.map((s) => {
              const isSelected = selectedDomain === s.domain;
              return (
                <div
                  key={s.domain}
                  onClick={() => setSelectedDomain(isSelected ? null : s.domain)}
                  className={
                    "flex items-start justify-between gap-3 py-2 cursor-pointer select-none " +
                    (isSelected
                      ? "bg-amber-50 border-l-4 border-amber-400 pl-2 pr-1"
                      : "hover:bg-gray-50 border-l-4 border-transparent pl-2 pr-1")
                  }
                  title={
                    isSelected
                      ? "Выбрано. Повторный клик — снять выбор; кнопки выше: «Анализ» перенесёт домен на «Починку сайтов», «Очистить» удалит позицию"
                      : "Клик — выбрать позицию, затем «Анализ» перенесёт домен на «Починку сайтов», «Очистить» удалит её из списка"
                  }
                >
                  <div className="min-w-0 flex-wrap">
                    <span className="font-semibold text-red-600 text-sm">{s.domain}</span>
                    <span className="text-gray-600 text-sm">
                      {" "}— {reasonToHuman(s.reason)} — {s.client_ip_port}
                    </span>
                  </div>
                  {/* ЧИПЫ (ШАГ E): бейджи вместо болтающегося текста.
                      Процесс — фиолетовый, списки — голубые, «не определён» — серые
                      (честный текст, никакой тишины). ×N и время остаются справа. */}
                  <div className="flex flex-wrap items-center justify-end gap-1.5 shrink-0 pt-0.5">
                    {s.proc ? (
                      <span
                        className="inline-flex items-center gap-1 rounded-full border border-purple-200 bg-purple-50 px-2 py-0.5 text-[11px] font-medium text-purple-700"
                        title={
                          s.procPath
                            ? "Процесс, который стучался на домен\nПуть exe: " + s.procPath
                            : "Процесс, который стучался на домен\nПуть exe не отдала система"
                        }
                      >
                        <Terminal size={10} /> {s.proc}
                      </span>
                    ) : (
                      <span className="rounded-full border border-gray-200 bg-gray-50 px-2 py-0.5 text-[11px] text-gray-400">
                        процесс не определён
                      </span>
                    )}
                    {s.lists && s.lists.length > 0 ? (
                      <span
                        className="inline-flex items-center gap-1 rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[11px] text-sky-700"
                        title="Наши списки, в которых найден домен"
                      >
                        в списках: {s.lists.join(", ")}
                      </span>
                    ) : (
                      <span className="rounded-full border border-gray-200 bg-gray-50 px-2 py-0.5 text-[11px] text-gray-400">
                        в списках отсутствует
                      </span>
                    )}
                    {s.count > 1 && (
                      <span className="font-semibold text-gray-500 text-[11px]">×{s.count}</span>
                    )}
                    <span className="text-gray-400 text-[11px]">{new Date(s.lastTs).toLocaleTimeString()}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="flex-1 bg-gray-900 rounded-xl p-4 flex flex-col min-h-[200px]">
        <div className="flex items-center gap-2 text-gray-400 mb-2 border-b border-gray-700 pb-2">
          <Activity size={16} /> <span className="text-sm font-semibold">Лог событий</span>
        </div>
        <div className="flex-1 overflow-y-auto text-green-400 font-mono text-sm break-all space-y-1">
          {visibleLogs.length === 0 ? <span className="text-gray-600">Ожидание действий...</span> : null}
          {visibleLogs.map((l, i) => <div key={i}>{l}</div>)}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
}
