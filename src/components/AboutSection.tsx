import { useEffect, useState, useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { open } from "@tauri-apps/plugin-shell";
import {
  getReleaseHistory,
  updateStore,
  type ReleaseInfo,
} from "@my-tauri-plugins/plugin-about-updates";

// Хост-хуки стора обновлений (SSOT стейта — в плагине): остановка обхода перед
// скачиванием/установкой (winws.exe и WinDivert держат файлы в bin/ заблокированными —
// иначе установщик падает с os error 32) и перезапуск после установки.
updateStore.setHooks({
  onBeforeInstall: async () => {
    try {
      await invoke("stop_bypass");
    } catch {
      // Остановка не удалась — не блокируем попытку установки/отката.
    }
  },
  onInstalled: () => {
    void relaunch();
  },
});
import {
  Info,
  RefreshCw,
  Download,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  History,
  RotateCcw,
} from "lucide-react";

const REPO_URL = "https://github.com/Sankyuubigan/dpi_gui";

/// Секция «О программе» (версия, репозиторий, обновления, откат).
/// Блок вверху вкладки «Настройки»; вкладки размонтируются при переключении,
/// поэтому весь стейт обновления/отката (проверка, прогресс, откат) живёт в
/// модульном updateStore (src/updateStore.ts) и переживает unmount —
/// этот компонент только рендерит его и зовёт действия.
export default function AboutSection() {
  const st = useSyncExternalStore(updateStore.subscribe, updateStore.getState);
  const [version, setVersion] = useState<string>("");

  // История релизов — перефетчируемый список без фоновой операции,
  // её потеря при unmount нечему ломать, поэтому она остаётся локальной.
  const [history, setHistory] = useState<ReleaseInfo[] | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selected, setSelected] = useState("");

  useEffect(() => {
    getVersion()
      .then(setVersion)
      .catch(() => setVersion("?"));
  }, []);

  const toggleHistory = async () => {
    if (history) {
      setHistory(null);
      return;
    }
    setHistoryLoading(true);
    try {
      setHistory(await getReleaseHistory());
    } catch (e: any) {
      updateStore.setRollbackMsg(e?.message || String(e));
    } finally {
      setHistoryLoading(false);
    }
  };

  const doRollback = async () => {
    const target = history?.find((r) => r.version === selected);
    if (!target) return;
    await updateStore.startRollback(target);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center gap-3 mb-4">
          <Info size={22} className="text-blue-600" />
          <h2 className="text-xl font-bold text-gray-800">О программе</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 border rounded-lg bg-gray-50">
            <h3 className="font-bold text-gray-700">DPI GUI</h3>
            <p className="text-xs text-gray-500">Графический интерфейс для обхода DPI.</p>
            <p className="mt-2 text-sm text-gray-600">
              Версия: <span className="font-semibold">{version || "..."}</span>
            </p>
          </div>

          <div className="p-4 border rounded-lg bg-gray-50">
            <h3 className="font-bold text-gray-700">Репозиторий</h3>
            <p className="text-xs text-gray-500">Исходный код и релизы проекта.</p>
            <button
              onClick={() => open(REPO_URL)}
              className="mt-2 flex items-center gap-2 text-blue-600 hover:text-blue-800 text-sm font-semibold"
            >
              <ExternalLink size={16} />
              Открыть на GitHub
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 className="text-lg font-bold text-gray-800 mb-4">Обновления</h2>

        <button
          onClick={() => updateStore.checkForUpdates()}
          disabled={st.status === "checking" || st.status === "downloading"}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-blue-700 disabled:opacity-50"
        >
          <RefreshCw size={18} className={st.status === "checking" ? "animate-spin" : ""} />
          Проверить обновления
        </button>

        <div className="mt-4">
          {st.status === "checking" && (
            <p className="text-gray-600 text-sm">Проверка наличия обновлений...</p>
          )}

          {st.status === "up-to-date" && (
            <div className="flex items-center gap-2 text-green-600">
              <CheckCircle2 size={18} />
              <span className="text-sm">У вас установлена актуальная версия.</span>
            </div>
          )}

          {st.status === "available" && st.update && (
            <div className="p-4 border border-blue-200 rounded-lg bg-blue-50">
              <p className="text-blue-800 font-semibold">
                Доступна новая версия: {st.update.version}
              </p>
              {st.update.date && (
                <p className="text-xs text-blue-600 mt-1">
                  Опубликовано: {new Date(st.update.date).toLocaleString()}
                </p>
              )}
              {st.update.body && (
                <p className="text-sm text-gray-700 mt-2 whitespace-pre-wrap">{st.update.body}</p>
              )}
              <button
                onClick={() => updateStore.startUpdate()}
                className="mt-3 flex items-center gap-2 bg-green-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-green-700"
              >
                <Download size={18} />
                Обновиться
              </button>
            </div>
          )}

          {st.status === "downloading" && (
            <div className="p-4 border rounded-lg bg-gray-50">
              <p className="text-sm text-gray-700 mb-2">Загрузка и установка обновления...</p>
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div
                  className="bg-blue-600 h-2.5 rounded-full transition-all"
                  style={{ width: `${st.progress}%` }}
                ></div>
              </div>
              <p className="text-xs text-gray-500 mt-1 text-right">{st.progress}%</p>
            </div>
          )}

          {st.status === "error" && (
            <div className="flex items-start gap-2 text-red-600">
              <AlertTriangle size={18} className="mt-0.5" />
              <div>
                <p className="text-sm font-semibold">Не удалось проверить обновления.</p>
                <p className="text-xs text-red-500 break-all">{st.errorMsg}</p>
                <p className="text-xs text-gray-500 mt-1">
                  Проверьте подключение к интернету или откройте релиз вручную на GitHub.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-gray-800 flex items-center gap-2">
            <History size={18} className="text-gray-500" />
            История релизов и откат
          </h2>
          <button
            onClick={toggleHistory}
            disabled={historyLoading || st.rollbackBusy}
            className="flex items-center gap-2 bg-gray-100 text-gray-700 px-4 py-2 rounded-md font-semibold hover:bg-gray-200 disabled:opacity-50"
          >
            <RefreshCw size={16} className={historyLoading ? "animate-spin" : ""} />
            {history ? "Скрыть" : "Показать"}
          </button>
        </div>

        {history && (
          <>
            <div className="flex flex-col sm:flex-row gap-2 items-stretch">
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                disabled={st.rollbackBusy}
                className="w-full border-gray-300 rounded-md shadow-sm p-2 border focus:border-blue-500 focus:ring-blue-500"
              >
                <option value="" disabled>
                  -- Выберите версию --
                </option>
                {history
                  .filter((r) => !r.isCurrent)
                  .map((r) => (
                    <option key={r.version} value={r.version}>
                      {r.pubDate
                        ? `v${r.version} — ${new Date(r.pubDate).toLocaleDateString()}`
                        : `v${r.version}`}
                    </option>
                  ))}
              </select>
              <button
                onClick={doRollback}
                disabled={!selected || st.rollbackBusy}
                className="flex items-center justify-center gap-2 bg-amber-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-amber-700 disabled:opacity-50 whitespace-nowrap"
              >
                <RotateCcw size={16} />
                Откатить
              </button>
            </div>

            {history.filter((r) => !r.isCurrent).length === 0 && (
              <p className="text-sm text-gray-500 mt-3">
                Нет более старых версий с установщиком.
              </p>
            )}

            {st.rollbackMsg && (
              <p className="text-sm text-gray-600 mt-3 break-all">{st.rollbackMsg}</p>
            )}
          </>
        )}
      </div>
    </div>
  );
}
