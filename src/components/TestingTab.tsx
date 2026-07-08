import { useEffect, type Dispatch, type SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Search, Globe, Activity } from "lucide-react";

export default function TestingTab({ profiles, config, log, setLog, url, setUrl, isTesting, setIsTesting }: {
  profiles: any[];
  config: any;
  log: string[];
  setLog: Dispatch<SetStateAction<string[]>>;
  url: string;
  setUrl: Dispatch<SetStateAction<string>>;
  isTesting: boolean;
  setIsTesting: Dispatch<SetStateAction<boolean>>;
}) {
  const appendLog = (msg: string) => {
    setLog((prev: string[]) => [...prev, msg].slice(-100));
  };

  useEffect(() => {
    // Слушаем логи winws во время теста
    const unlisten = listen<string>("log", (event) => {
      appendLog(`[СИСТЕМА] ${event.payload}`);
    });
    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const runDeepAnalysis = async () => {
    if (!url) return;
    setIsTesting(true);
    setLog([`[Анализ] Запуск глубокого анализа для: ${url}...`, "Это может занять до 20 секунд. Открывается фоновый браузер..."]);
    
    try {
      const result: string = await invoke("run_deep_analysis", { url });
      appendLog(result);
    } catch (e: any) {
      appendLog(`[Ошибка]: ${e}`);
    } finally {
      setIsTesting(false);
    }
  };

  const runProfileTest = async () => {
    if (!url) return;
    setIsTesting(true);
    setLog([`[Тест] Пинг сайта ${url} по всем профилям...`]);

    try {
      for (const p of profiles) {
        appendLog(`-> Тест профиля: ${p.name}`);
        const result: string = await invoke("test_profile", { 
          profileName: p.name, 
          url, 
          gameFilter: config.game_filter 
        });
        appendLog(`   Результат: ${result}`);
      }
      appendLog("=== ТЕСТИРОВАНИЕ ЗАВЕРШЕНО ===");
    } catch (e: any) {
      appendLog(`[Ошибка]: ${e}`);
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 className="text-xl font-bold text-gray-800 mb-4">Инструменты тестирования</h2>
        
        <div className="flex gap-2 mb-4">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-3 text-gray-400" size={20} />
            <input 
              type="text" 
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Введите домен (например, twitter.com)"
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
            />
          </div>
        </div>

        <div className="flex gap-3">
          <button 
            onClick={runDeepAnalysis}
            disabled={isTesting}
            className="flex-1 flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold"
          >
            <Search size={18} /> Глубокий анализ (Поиск доменов)
          </button>
          <button 
            onClick={runProfileTest}
            disabled={isTesting}
            className="flex-1 flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold"
          >
            <Activity size={18} /> Прогнать по всем профилям
          </button>
        </div>
      </div>

      <div className="flex-1 bg-gray-900 rounded-xl p-4 flex flex-col min-h-[300px]">
        <div className="text-gray-400 mb-2 border-b border-gray-700 pb-2 text-sm font-semibold">
          Результаты тестирования
        </div>
        <div className="flex-1 overflow-y-auto text-blue-300 font-mono text-sm break-all space-y-1 whitespace-pre-wrap">
          {log.length === 0 ? <span className="text-gray-600">Ожидание...</span> : null}
          {log.map((l, i) => <div key={i}>{l}</div>)}
        </div>
      </div>
    </div>
  );
}