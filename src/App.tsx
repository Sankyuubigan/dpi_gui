import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import ControlTab from "./components/ControlTab";
import SettingsTab from "./components/SettingsTab";
import ProfilesTab from "./components/ProfilesTab";
import SiteFixTab from "./components/SiteFixTab";
import type { LogEntry } from "./components/TestingLogPanel";

const MAX_LOG_LINES = 5000; // лог живёт ВСЮ сессию приложения (PRP §7.1)
const MAX_SUSPICIONS = 200; // список подозрений — рабочая память (PRP §7.2)

export interface Suspicion {
  domain: string;
  /// Машинная причина: "rst" | "retrans" (человекочитаемую берём через reasonToHuman).
  reason: string;
  client_ip_port: string;
  /// ШАГ D (PRP §7.5): названия наших списков, где нашёлся домен; пусто = нигде.
  lists: string[];
  /// ШАГ E (PRP §7.6): процесс, который стучался; пустая строка = не определился.
  proc: string;
  /// Полный путь exe того же процесса (хинт при наведении мыши);
  /// пустая строка = путь не отдала система.
  procPath: string;
  lastTs: number; // observed_at_ms последнего события по домену
  count: number; // сколько событий по этому домену было (дедуп по домену)
}

/// Найденное решение анализа (кнопка «Починить сайт»). Контракт serde —
/// в src-tauri/src/site_solution.rs (SSOT), поля в camelCase.
export type SolutionAction =
  | { type: "addToBypassList"; domains: string[] }
  | { type: "addToExcludeList"; domains: string[] }
  | { type: "writeHosts"; ip: string; domain: string };

export interface SiteSolution {
  found: boolean;
  actions: SolutionAction[];
  summary: string;
  noneReason: string | null;
}

export default function App() {
  const [activeTab, setActiveTab] = useState("control");
  const [isRunning, setIsRunning] = useState(false);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [config, setConfig] = useState<any>({ selected_profile: "", game_filter: false });
  const [testingLog, setTestingLog] = useState<LogEntry[]>([]);
  const [testingUrl, setTestingUrl] = useState("youtube.com");
  const [testingIsTesting, setTestingIsTesting] = useState(false);
  // Решение последнего анализа (кнопка «Починить сайт»). null = анализа ещё
  // не было / решение неприменимо. Живёт здесь же, чтобы переживать смену вкладки.
  const [siteSolution, setSiteSolution] = useState<SiteSolution | null>(null);

  // Лог и список подозрений живут ЗДЕСЬ, в App, а НЕ в ControlTab:
  // App никогда не размонтируется при смене вкладок, поэтому лог сохраняется
  // на всё время работы приложения (PRP §7.1, баг «лог чистится при смене вкладки»).
  const [logs, setLogs] = useState<string[]>([]);
  const [suspicions, setSuspicions] = useState<Suspicion[]>([]);

  const logMsg = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${time}] ${msg}`].slice(-MAX_LOG_LINES));
  };

  // Слушатели бэкенд-событий: «log» (общий журнал) и «domain_discovery»
  // (фоновой детектор подозрительных доменов). Дедуп по домену: повтор события
  // по уже известному домену обновляет его строку (причина/ip/время/счётчик),
  // новых строк не создаёт (PRP §7.2).
  useEffect(() => {
    const unLog = listen<string>("log", (event) => {
      logMsg(event.payload);
    });
    const unDiscovery = listen<any>("domain_discovery", (event) => {
      const ev = event.payload;
      const lists: string[] = ev.lists || [];
      const proc: string = ev.proc_name || "";
      const procPath: string = ev.proc_path || "";
      setSuspicions(prev => {
        const idx = prev.findIndex(s => s.domain === ev.domain);
        if (idx >= 0) {
          const old = prev[idx];
          const next = [...prev];
          next[idx] = {
            ...old,
            reason: ev.reason,
            client_ip_port: ev.client_ip_port,
            lists,
            proc,
            procPath,
            lastTs: ev.observed_at_ms || Date.now(),
            count: old.count + 1,
          };
          return next;
        }
        const cur: Suspicion = {
          domain: ev.domain,
          reason: ev.reason,
          client_ip_port: ev.client_ip_port,
          lists,
          proc,
          procPath,
          lastTs: ev.observed_at_ms || Date.now(),
          count: 1,
        };
        return [...prev, cur].slice(-MAX_SUSPICIONS);
      });
      // Человекочитаемую строку "[БЛОКИРОВКА?] …" в лог пишет сам бэкенд через
      // app_log (listen("log") выше) — С ТЕКСТОМ СПИСКОВ (ШАГ D). Здесь ручное
      // дублирование НЕ нужно: раньше фронт дублировал строку без списков (баг).
    });

    return () => {
      unLog.then(f => f());
      unDiscovery.then(f => f());
    };
  }, []);

  // Загрузка конфигурации при старте
  useEffect(() => {
    async function init() {
      try {
        await invoke("init_app");
        const loadedConfig: any = await invoke("get_config");
        setConfig(loadedConfig);
        const loadedProfiles: any[] = await invoke("get_profiles");
        setProfiles(loadedProfiles);

        // Проверяем, запущен ли процесс
        const status: boolean = await invoke("check_status");
        setIsRunning(status);
      } catch (e) {
        console.error("Initialization error:", e);
      }
    }
    init();

    // Периодическая проверка статуса
    const interval = setInterval(async () => {
      const status: boolean = await invoke("check_status");
      setIsRunning(status);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const saveConfig = async (newConfig: any) => {
    setConfig(newConfig);
    await invoke("save_config", { config: newConfig });
  };

  // Перенос домена из списка ошибок сети на вкладку «Починка сайтов»:
  // подставляем его в поле анализа (testingUrl — SSOT, живёт здесь) и
  // переключаем вкладку. SiteFixTab смонтируется с уже заполненным полем.
  const sendToSiteFix = (domain: string) => {
    setTestingUrl(domain);
    setActiveTab("sitefix");
  };

  return (
    <div className="flex flex-col h-full bg-gray-50">
      {/* Навигация */}
      <div className="flex border-b bg-white shadow-sm">
        <button
          className={`px-4 py-3 font-semibold ${activeTab === "control" ? "text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          onClick={() => setActiveTab("control")}
        >
          Управление
        </button>
        <button
          className={`px-4 py-3 font-semibold ${activeTab === "settings" ? "text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          onClick={() => setActiveTab("settings")}
        >
          Настройки
        </button>
        <button
          className={`px-4 py-3 font-semibold ${activeTab === "profiles" ? "text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          onClick={() => setActiveTab("profiles")}
        >
          Профили обхода
        </button>
        <button
          className={`px-4 py-3 font-semibold ${activeTab === "sitefix" ? "text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          onClick={() => setActiveTab("sitefix")}
        >
          Починка сайтов
        </button>
      </div>

      {/* Содержимое вкладок */}
      <div className="flex-1 overflow-auto p-4">
        {activeTab === "control" && (
          <ControlTab
            isRunning={isRunning}
            profiles={profiles}
            config={config}
            saveConfig={saveConfig}
            logs={logs}
            suspicions={suspicions}
            setSuspicions={setSuspicions}
            logMsg={logMsg}
            onFixDomain={sendToSiteFix}
          />
        )}
        {activeTab === "settings" && <SettingsTab />}
        {activeTab === "profiles" && (
          <ProfilesTab
            profiles={profiles}
            setProfiles={setProfiles}
            config={config}
            log={testingLog}
            setLog={setTestingLog}
            url={testingUrl}
            setUrl={setTestingUrl}
            isTesting={testingIsTesting}
            setIsTesting={setTestingIsTesting}
          />
        )}
        {activeTab === "sitefix" && (
          <SiteFixTab
            log={testingLog}
            setLog={setTestingLog}
            url={testingUrl}
            setUrl={setTestingUrl}
            isTesting={testingIsTesting}
            setIsTesting={setTestingIsTesting}
            solution={siteSolution}
            setSolution={setSiteSolution}
          />
        )}
      </div>
    </div>
  );
}
