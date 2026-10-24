import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Edit3, Eye, FileText, ListFilter } from "lucide-react";
import AboutSection from "./AboutSection";

/// Вкладка «Настройки»: секция «О программе» сверху, ниже — управление
/// файлами списков (General / Exclude / DoH / hosts) и режимом наблюдения.
export default function SettingsTab() {
  const [config, setConfig] = useState<any>(null);

  useEffect(() => {
    (async () => {
      try {
        const cfg: any = await invoke("get_config");
        setConfig(cfg);
      } catch (e) {
        console.error("get_config:", e);
      }
    })();
  }, []);

  const saveMode = async (mode: string) => {
    if (!config) return;
    const next = { ...config, domain_monitor_mode: mode };
    setConfig(next);
    try {
      await invoke("save_config", { config: next });
    } catch (e) {
      console.error("save_config:", e);
    }
  };

  const openFile = async (type: string) => {
    try { await invoke("open_file", { fileType: type }); }
    catch (e) { console.error(e); }
  };

  return (
    <div className="flex flex-col gap-4">
      <AboutSection />

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
              <h3 className="font-bold text-gray-700">DoH-серверы</h3>
              <p className="text-xs text-gray-500">Список сервисов подмены DNS для «Теста подмены DNS».</p>
            </div>
            <button onClick={() => openFile("doh_services")} className="flex items-center gap-2 bg-blue-100 text-blue-700 px-4 py-2 rounded-md font-semibold hover:bg-blue-200">
              <ListFilter size={18} />
            </button>
          </div>

          <div className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 hover:bg-gray-100 transition">
            <div>
              <h3 className="font-bold text-gray-700">Файл hosts</h3>
              <p className="text-xs text-gray-500">C:\Windows\System32\drivers\etc\hosts (записи приложения помечены DPI_GUI).</p>
            </div>
            <button onClick={() => openFile("hosts")} className="flex items-center gap-2 bg-blue-100 text-blue-700 px-4 py-2 rounded-md font-semibold hover:bg-blue-200">
              <FileText size={18} />
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center gap-2 mb-4">
          <Eye size={18} className="text-blue-600" />
          <h2 className="text-xl font-bold text-gray-800">Наблюдение за блокировками</h2>
        </div>
        <p className="text-gray-500 mb-4 text-sm">
          Фоновый детектор ловит «сломанные» домены (входящий RST от сервера или
          повторные отправки данных на TLS:443) во время работы обхода. Списки при
          этом не изменяются — события только в лог. Режим применяется после
          перезапуска обхода.
        </p>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Режим детектора</label>
          <select
            value={config?.domain_monitor_mode || "observe"}
            onChange={(e) => saveMode(e.target.value)}
            disabled={!config}
            className="w-full border-gray-300 rounded-md shadow-sm p-2 border focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="observe">Наблюдение (только лог)</option>
            <option value="off">Выключено</option>
          </select>
        </div>
      </div>
    </div>
  );
}
