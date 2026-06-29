import { invoke } from "@tauri-apps/api/core";
import { FolderOpen, Edit3 } from "lucide-react";

export default function SettingsTab() {
  
  const openFile = async (type: string) => {
    try { await invoke("open_file", { fileType: type }); } 
    catch (e) { console.error(e); }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 className="text-xl font-bold text-gray-800 mb-4">Управление списками</h2>
        <p className="text-gray-500 mb-6 text-sm">
          Списки сохраняются в защищенной директории AppData и используются активными профилями обхода.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 hover:bg-gray-100 transition">
            <div>
              <h3 className="font-bold text-gray-700">General List</h3>
              <p className="text-xs text-gray-500">Основной список доменов для обхода.</p>
            </div>
            <button onClick={() => openFile("list_general")} className="flex items-center gap-2 bg-blue-100 text-blue-700 px-4 py-2 rounded-md font-semibold hover:bg-blue-200">
              <Edit3 size={18} />
            </button>
          </div>

          <div className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 hover:bg-gray-100 transition">
            <div>
              <h3 className="font-bold text-gray-700">Exclude List</h3>
              <p className="text-xs text-gray-500">Домены-исключения (не пускать через обход).</p>
            </div>
            <button onClick={() => openFile("list_exclude")} className="flex items-center gap-2 bg-blue-100 text-blue-700 px-4 py-2 rounded-md font-semibold hover:bg-blue-200">
              <Edit3 size={18} />
            </button>
          </div>

          <div className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 hover:bg-gray-100 transition">
            <div>
              <h3 className="font-bold text-gray-700">Google List</h3>
              <p className="text-xs text-gray-500">Список доменов для сервисов Google.</p>
            </div>
            <button onClick={() => openFile("list_google")} className="flex items-center gap-2 bg-blue-100 text-blue-700 px-4 py-2 rounded-md font-semibold hover:bg-blue-200">
              <Edit3 size={18} />
            </button>
          </div>

          <div className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 hover:bg-gray-100 transition">
            <div>
              <h3 className="font-bold text-gray-700">Профили обхода</h3>
              <p className="text-xs text-gray-500">Конфигурация аргументов winws.</p>
            </div>
            <button onClick={() => openFile("profiles")} className="flex items-center gap-2 bg-gray-200 text-gray-800 px-4 py-2 rounded-md font-semibold hover:bg-gray-300">
              <FolderOpen size={18} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}