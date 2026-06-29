import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Play, Square, Activity } from "lucide-react";

export default function ControlTab({ isRunning, profiles, config, saveConfig }: any) {
  const [logs, setLogs] = useState<string[]>([]);

  const logMsg = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [`[${time}] ${msg}`, ...prev].slice(0, 100));
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
            <div className={`w-3 h-3 rounded-full ${isRunning ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
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

      <div className="flex-1 bg-gray-900 rounded-xl p-4 flex flex-col min-h-[200px]">
        <div className="flex items-center gap-2 text-gray-400 mb-2 border-b border-gray-700 pb-2">
          <Activity size={16} /> <span className="text-sm font-semibold">Лог событий</span>
        </div>
        <div className="flex-1 overflow-y-auto text-green-400 font-mono text-sm break-all space-y-1">
          {logs.length === 0 ? <span className="text-gray-600">Ожидание действий...</span> : null}
          {logs.map((l, i) => <div key={i}>{l}</div>)}
        </div>
      </div>
    </div>
  );
}