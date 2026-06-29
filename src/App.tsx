import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import ControlTab from "./components/ControlTab";
import SettingsTab from "./components/SettingsTab";
import TestingTab from "./components/TestingTab";

export default function App() {
  const [activeTab, setActiveTab] = useState("control");
  const [isRunning, setIsRunning] = useState(false);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [config, setConfig] = useState<any>({ selected_profile: "", game_filter: false });

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
          Списки и Настройки
        </button>
        <button
          className={`px-4 py-3 font-semibold ${activeTab === "testing" ? "text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          onClick={() => setActiveTab("testing")}
        >
          Инструменты
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
          />
        )}
        {activeTab === "settings" && <SettingsTab />}
        {activeTab === "testing" && <TestingTab profiles={profiles} config={config} />}
      </div>
    </div>
  );
}