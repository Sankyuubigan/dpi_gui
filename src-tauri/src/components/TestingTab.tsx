import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Search, Globe, Activity, ShieldQuestion, Stethoscope, ClipboardCopy } from "lucide-react";

export default function TestingTab({ profiles, setProfiles, config, log, setLog, url, setUrl, isTesting, setIsTesting }: {
  profiles: any[];
  setProfiles: Dispatch<SetStateAction<any[]>>;
  config: any;
  log: string[];
  setLog: Dispatch<SetStateAction<string[]>>;
  url: string;
  setUrl: Dispatch<SetStateAction<string>>;
  isTesting: boolean;
  setIsTesting: Dispatch<SetStateAction<boolean>>;
}) {
  const [dnsIp, setDnsIp] = useState("1.1.1.1"); // Cloudflare по умолчанию
  const [diag, setDiag] = useState<any>(null);

  const appendLog = (msg: string) => {
    setLog((prev: string[]) => [...prev, msg].slice(-100));
  };

  useEffect(() => {
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
    setLog([
      `[Анализ] Запуск анализа доменов для: ${url}...`,
      "Фоновый браузер запущен. Сбор доменов и проверка их доступности через обход (займет до ~25 сек)..."
    ]);

    try {
      const result: string = await invoke("run_domain_analysis", { url });
      appendLog(result);
    } catch (e: any) {
      appendLog(`[Ошибка анализа]: ${e}`);
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

  const runDnsTest = async () => {
    if (!url || !dnsIp) return;
    setIsTesting(true);
    setLog([`[Тест DNS] Проверка сайта ${url} через кастомный DNS (${dnsIp})...`]);

    try {
      const result: string = await invoke("test_dns", { url, dnsIp });
      appendLog(result);
    } catch (e: any) {
      appendLog(`[Ошибка DNS Теста]: ${e}`);
    } finally {
      setIsTesting(false);
    }
  };

  const runDiagnostics = async () => {
    if (!url) return;
    setIsTesting(true);
    setDiag(null);
    setLog([
      `[Диагностика] Комплексная проверка соединения для: ${url}...`,
      "Это займёт до ~1-2 минут: пробы DNS, WinDivert, connect, и прогон desync-техник.",
      "Если какой-то инструмент не сработает — он будет пропущен, диагностика продолжится."
    ]);

    try {
      const report: any = await invoke("run_diagnostics", { url, gameFilter: config.game_filter });
      setDiag(report);
      appendLog("=== ДИАГНОСТИКА ЗАВЕРШЕНА ===");
      appendLog(`Отпечаток: ${report.fingerprint}`);
      // Обновляем список профилей (мог добавиться авто-профиль)
      try {
        const loaded: any[] = await invoke("get_profiles");
        setProfiles(loaded);
      } catch { /* ignore */ }
    } catch (e: any) {
      appendLog(`[Ошибка диагностики]: ${e}`);
    } finally {
      setIsTesting(false);
    }
  };

  const copyReport = () => {
    if (!diag) return;
    const parts = [
      "=== ОТЧЁТ ДИАГНОСТИКИ ===",
      `Отпечаток: ${diag.fingerprint}`,
      "",
      "Рекомендация:",
      diag.recommendation,
      "",
      "Техники:",
      ...(diag.techniques || []).map((t: any) => `  - ${t.name}: ${t.passed ? "ПРОХОДИТ" : t.detail}`),
      "",
      diag.generated_profile_name
        ? `Авто-профиль: ${diag.generated_profile_name} (проверен: ${diag.generated_profile_verified === true ? "ДА" : diag.generated_profile_verified === false ? "НЕТ" : "н/д"})`
        : "Авто-профиль: не создан",
    ];
    navigator.clipboard.writeText(parts.join("\n")).then(
      () => appendLog("[Диагностика] Отчёт скопирован в буфер обмена."),
      () => appendLog("[Диагностика] Не удалось скопировать отчёт.")
    );
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

        <div className="flex flex-col gap-3">
          <div className="flex gap-3">
            <button
              onClick={runDeepAnalysis}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
            >
              <Search size={18} /> Анализ доменов
            </button>
            <button
              onClick={runProfileTest}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
            >
              <Activity size={18} /> Тест профилей
            </button>
          </div>

          <div className="flex gap-3 mt-2 items-center border-t border-gray-100 pt-4">
            <input
              type="text"
              value={dnsIp}
              onChange={(e) => setDnsIp(e.target.value)}
              placeholder="IP DNS (например 1.1.1.1)"
              className="w-1/3 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 outline-none text-sm"
              title="Введите кастомный IP-адрес DNS-сервера"
            />
            <button
              onClick={runDnsTest}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
            >
              <ShieldQuestion size={18} /> Тест подмены DNS
            </button>
          </div>

          <div className="flex gap-3 mt-2 border-t border-gray-100 pt-4">
            <button
              onClick={runDiagnostics}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-rose-600 hover:bg-rose-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
            >
              <Stethoscope size={18} /> Диагностика соединения + авто-профиль
            </button>
            <button
              onClick={copyReport}
              disabled={!diag}
              className="flex items-center justify-center gap-2 bg-gray-700 hover:bg-gray-800 disabled:bg-gray-400 text-white px-4 py-2 rounded-lg font-bold transition"
              title="Скопировать отчёт для разработчика"
            >
              <ClipboardCopy size={18} /> Отчёт
            </button>
          </div>
        </div>
      </div>

      {diag && (
        <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-100 text-sm">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-gray-800">Результат диагностики</h3>
            {diag.generated_profile_name ? (
              <span className={`px-2 py-1 rounded text-xs font-bold ${diag.generated_profile_verified === true ? "bg-green-100 text-green-700" : diag.generated_profile_verified === false ? "bg-red-100 text-red-700" : "bg-gray-100 text-gray-600"}`}>
                {diag.generated_profile_verified === true ? "ПРОФИЛЬ РАБОТАЕТ" : diag.generated_profile_verified === false ? "ПРОФИЛЬ НЕ ПРОШЁЛ" : "ПРОФИЛЬ СОЗДАН"}
              </span>
            ) : null}
          </div>

          <div className="grid grid-cols-2 gap-2 mb-3 text-xs">
            <div>Права админа: <b>{diag.admin_ok ? "ДА" : "НЕТ"}</b></div>
            <div>WinDivert: <b className={diag.windivert_ok ? "text-green-600" : "text-red-600"}>{diag.windivert_ok ? "OK" : "FAIL"}</b></div>
            <div>IPv6: <b>{diag.ipv6_available ? "есть" : "нет"}</b></div>
            <div>CONNECT 443: <b>{diag.connect_443}</b></div>
            <div>HTTPS (без обхода): <b>{diag.tls_sni}</b></div>
            <div>QUIC/UDP 443: <b>{diag.quic}</b></div>
          </div>

          <div className="mb-3">
            <div className="font-semibold text-gray-700 mb-1">Прогон desync-техник:</div>
            <div className="flex flex-wrap gap-1">
              {(diag.techniques || []).map((t: any) => (
                <span key={t.name} className={`px-2 py-0.5 rounded text-xs ${t.passed ? "bg-green-100 text-green-700" : "bg-red-50 text-red-500"}`} title={t.detail}>
                  {t.name}: {t.passed ? "OK" : "x"}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-gray-900 text-blue-300 font-mono text-xs p-3 rounded break-all whitespace-pre-wrap mb-2">
            {diag.fingerprint}
          </div>

          <div className="text-gray-700 whitespace-pre-wrap break-words">{diag.recommendation}</div>

          {diag.generated_profile_name && (
            <div className="mt-2">
              <div className="font-semibold text-gray-700">Авто-профиль: {diag.generated_profile_name}</div>
              <div className="bg-gray-100 text-gray-700 font-mono text-xs p-2 rounded break-all whitespace-pre-wrap mt-1">
                {diag.generated_profile_args}
              </div>
              <div className="text-xs text-gray-500 mt-1">Профиль уже добавлен в список и выбирается в вкладке «Управление».</div>
            </div>
          )}
        </div>
      )}

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
