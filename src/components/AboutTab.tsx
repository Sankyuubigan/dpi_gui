import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { open } from "@tauri-apps/plugin-shell";
import { Info, RefreshCw, Download, ExternalLink, CheckCircle2, AlertTriangle } from "lucide-react";

type Status =
  | "idle"
  | "checking"
  | "up-to-date"
  | "available"
  | "downloading"
  | "error";

const REPO_URL = "https://github.com/Sankyuubigan/dpi_gui";

export default function AboutTab() {
  const [version, setVersion] = useState<string>("");
  const [status, setStatus] = useState<Status>("idle");
  const [update, setUpdate] = useState<Update | null>(null);
  const [progress, setProgress] = useState(0);
  const [isDownloading, setIsDownloading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    getVersion()
      .then(setVersion)
      .catch(() => setVersion("?"));
  }, []);

  const checkForUpdates = async () => {
    setStatus("checking");
    setErrorMsg("");
    try {
      const found = await check();
      if (found) {
        setUpdate(found);
        setStatus("available");
      } else {
        setStatus("up-to-date");
      }
    } catch (e: any) {
      setErrorMsg(e?.message || String(e));
      setStatus("error");
    }
  };

  const doUpdate = async () => {
    if (!update) return;
    setStatus("downloading");
    setIsDownloading(true);
    setProgress(0);
    try {
      // Останавливаем обход перед установкой: иначе winws.exe / WinDivert
      // держат файлы в bin/ заблокированными и установщик не сможет их перезаписать.
      try {
        await invoke("stop_bypass");
      } catch (_) {
        // Даже если остановить не удалось — продолжаем попытку обновления.
      }
      let downloaded = 0;
      let total = 0;
      await update.downloadAndInstall((event) => {
        if (event.event === "Started") {
          total = event.data.contentLength ?? 0;
        } else if (event.event === "Progress") {
          downloaded += event.data.chunkLength;
          if (total > 0) setProgress(Math.round((downloaded / total) * 100));
        }
      });
      await relaunch();
    } catch (e: any) {
      setErrorMsg(e?.message || String(e));
      setStatus("error");
      setIsDownloading(false);
    }
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
          onClick={checkForUpdates}
          disabled={status === "checking" || status === "downloading"}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-blue-700 disabled:opacity-50"
        >
          <RefreshCw size={18} className={status === "checking" ? "animate-spin" : ""} />
          Проверить обновления
        </button>

        <div className="mt-4">
          {status === "checking" && (
            <p className="text-gray-600 text-sm">Проверка наличия обновлений...</p>
          )}

          {status === "up-to-date" && (
            <div className="flex items-center gap-2 text-green-600">
              <CheckCircle2 size={18} />
              <span className="text-sm">У вас установлена актуальная версия.</span>
            </div>
          )}

          {status === "available" && update && (
            <div className="p-4 border border-blue-200 rounded-lg bg-blue-50">
              <p className="text-blue-800 font-semibold">
                Доступна новая версия: {update.version}
              </p>
              {update.date && (
                <p className="text-xs text-blue-600 mt-1">
                  Опубликовано: {new Date(update.date).toLocaleString()}
                </p>
              )}
              {update.body && (
                <p className="text-sm text-gray-700 mt-2 whitespace-pre-wrap">{update.body}</p>
              )}
              <button
                onClick={doUpdate}
                className="mt-3 flex items-center gap-2 bg-green-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-green-700 disabled:opacity-50"
                disabled={isDownloading}
              >
                <Download size={18} />
                Обновиться
              </button>
            </div>
          )}

          {status === "downloading" && (
            <div className="p-4 border rounded-lg bg-gray-50">
              <p className="text-sm text-gray-700 mb-2">Загрузка и установка обновления...</p>
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div
                  className="bg-blue-600 h-2.5 rounded-full transition-all"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
              <p className="text-xs text-gray-500 mt-1 text-right">{progress}%</p>
            </div>
          )}

          {status === "error" && (
            <div className="flex items-start gap-2 text-red-600">
              <AlertTriangle size={18} className="mt-0.5" />
              <div>
                <p className="text-sm font-semibold">Не удалось проверить обновления.</p>
                <p className="text-xs text-red-500 break-all">{errorMsg}</p>
                <p className="text-xs text-gray-500 mt-1">
                  Проверьте подключение к интернету или откройте релиз вручную на GitHub.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
