import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Search, Globe, Activity, ShieldQuestion, Stethoscope, ClipboardCopy, CheckCircle2, XCircle } from "lucide-react";

export type LogKind = "info" | "ok" | "fail" | "sys";
export type LogEntry = { text: string; kind: LogKind };

export default function TestingTab({ profiles, setProfiles, config, log, setLog, url, setUrl, isTesting, setIsTesting }: {
  profiles: any[];
  setProfiles: Dispatch<SetStateAction<any[]>>;
  config: any;
  log: LogEntry[];
  setLog: Dispatch<SetStateAction<LogEntry[]>>;
  url: string;
  setUrl: Dispatch<SetStateAction<string>>;
  isTesting: boolean;
  setIsTesting: Dispatch<SetStateAction<boolean>>;
}) {
  const [dnsIp, setDnsIp] = useState("1.1.1.1"); // Cloudflare по умолчанию
  const [diag, setDiag] = useState<any>(null);
  const [testProgress, setTestProgress] = useState<{ total: number; done: number; current: string } | null>(null);

  const appendEntry = (text: string, kind: LogKind) => {
    setLog((prev: LogEntry[]) => [...prev, { text, kind }].slice(-100));
  };

  const appendLog = (msg: string) => {
    appendEntry(msg, "info");
  };

  useEffect(() => {
    const unlisten = listen<string>("log", (event) => {
      appendEntry(`[СИСТЕМА] ${event.payload}`, "sys");
    });
    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const runDeepAnalysis = async () => {
    if (!url) return;
    setIsTesting(true);
    setLog([
      { text: `[Анализ] Запуск анализа доменов для: ${url}...`, kind: "info" },
      { text: "Фоновый браузер запущен. Сбор доменов и проверка их доступности через обход (займет до ~25 сек)...", kind: "info" }
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
    const total = profiles.length;
    setTestProgress({ total, done: 0, current: "..." });
    setLog([{ text: `[Тест] Пинг сайта ${url} по всем профилям (всего ${total})...`, kind: "info" }]);
    const startTime = Date.now();
    const flatUrl = url.replace(/^https?:\/\//, "").split("/")[0];
    const counts: Record<string, number> = {};
    const successes: string[] = [];
    const failures: { name: string; verdict: string }[] = [];

    try {
      for (let i = 0; i < profiles.length; i++) {
        const p = profiles[i];
        const num = i + 1;
        setTestProgress({ total, done: i, current: p.name });
        const isAuto = String(p.name ?? "").startsWith("Авто-профиль");
        appendLog(
          `[${num}/${total}] Тест профиля: ${p.name}` +
          (isAuto ? ` — авто-профиль, привязан к своему домену (на ${flatUrl} не показателен)` : "")
        );
        try {
          const outcome: any = await invoke("test_profile", {
            profileName: p.name,
            url,
            gameFilter: config.game_filter
          });
          const secs = ((outcome.elapsed_ms ?? 0) / 1000).toFixed(1);
          if (outcome.ok) {
            appendEntry(`   Результат: ${outcome.verdict || "УСПЕХ"} · ${secs}с`, "ok");
            counts["УСПЕХ"] = (counts["УСПЕХ"] ?? 0) + 1;
            successes.push(String(p.name ?? ""));
          } else {
            appendEntry(`   Результат: ${outcome.verdict || "Неудача"} · ${secs}с`, "fail");
            if (outcome.detail && outcome.detail !== outcome.verdict) {
              appendLog(`   Причина: ${outcome.detail}`);
            }
            const key = outcome.verdict || "Неудача";
            counts[key] = (counts[key] ?? 0) + 1;
            failures.push({ name: String(p.name ?? ""), verdict: outcome.verdict || "Неудача" });
          }
        } catch (e: any) {
          appendEntry(`   Результат: Ошибка теста: ${e}`, "fail");
          counts["Ошибка теста"] = (counts["Ошибка теста"] ?? 0) + 1;
          failures.push({ name: String(p.name ?? ""), verdict: "Ошибка теста" });
        }
      }
      setTestProgress({ total, done: total, current: "" });
      const totalSecs = ((Date.now() - startTime) / 1000).toFixed(0);
      appendLog(`=== ТЕСТИРОВАНИЕ ЗАВЕРШЕНО (${totalSecs}с) ===`);
      const summary = Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(" · ");
      appendLog(`Итог: ${summary}`);
      if (successes.length > 0) {
        appendEntry(`Успешные профили: ${successes.join(", ")}`, "ok");
      } else {
        appendEntry("Успешных профилей нет", "fail");
      }
      if (failures.length > 0) {
        appendEntry(
          `Неудачные профили: ${failures.map((f) => `${f.name} (${f.verdict})`).join(", ")}`,
          "fail"
        );
      }
    } catch (e: any) {
      appendLog(`[Ошибка]: ${e}`);
    } finally {
      setTestProgress(null);
      setIsTesting(false);
    }
  };

  const runDnsTest = async () => {
    if (!url || !dnsIp) return;
    setIsTesting(true);
    setLog([{ text: `[Тест DNS] Проверка сайта ${url} через кастомный DNS (${dnsIp})...`, kind: "info" }]);

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
      { text: `[Диагностика] Комплексная проверка соединения для: ${url}...`, kind: "info" },
      { text: "Это займёт до ~1-2 минут: пробы DNS, WinDivert, connect, и прогон desync-техник.", kind: "info" },
      { text: "Если какой-то инструмент не сработает — он будет пропущен, диагностика продолжится.", kind: "info" }
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

  const copyLogs = () => {
    if (log.length === 0) return;
    navigator.clipboard.writeText(log.map((l) => l.text).join("\n")).then(
      () => appendLog("[Лог] Скопировано в буфер обмена."),
      () => appendLog("[Лог] Не удалось скопировать в буфер обмена.")
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
              list="dns-presets"
              value={dnsIp}
              onChange={(e) => setDnsIp(e.target.value)}
              placeholder="IP DNS или DoH (например 1.1.1.1 или https://xbox-dns.ru/dns-query)"
              className="w-1/3 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 outline-none text-sm"
              title="Кастомный DNS-сервер: IP (1.1.1.1) или DoH-сервис подмены DNS (https://xbox-dns.ru/dns-query, https://geohide.ru/dns-query)"
            />
            <datalist id="dns-presets">
              <option value="1.1.1.1">Cloudflare</option>
              <option value="https://xbox-dns.ru/dns-query">xbox-dns.ru (DoH)</option>
              <option value="https://geohide.ru/dns-query">geohide.ru (DoH)</option>
            </datalist>
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
          </div>
        </div>
      </div>

      {testProgress && (
        <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-100">
          <div className="flex justify-between items-center text-xs text-gray-600 mb-1">
            <span className="font-semibold">Тест профилей</span>
            <span>{testProgress.done}/{testProgress.total}</span>
          </div>
          <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full bg-indigo-600 transition-all duration-300"
              style={{ width: `${testProgress.total > 0 ? (testProgress.done / testProgress.total) * 100 : 0}%` }}
            ></div>
          </div>
          {testProgress.current && (
            <div className="text-xs text-gray-500 mt-1.5 animate-pulse">Сейчас: {testProgress.current}</div>
          )}
        </div>
      )}

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

          {diag.existing_profiles && diag.existing_profiles.length > 0 && (
            <div className="mb-3">
              <div className="font-semibold text-gray-700 mb-1">Ваши профили:</div>
              <div className="flex flex-wrap gap-1">
                {diag.existing_profiles.map((t: any) => (
                  <span key={t.name} className={`px-2 py-0.5 rounded text-xs ${t.passed ? "bg-green-100 text-green-700" : "bg-red-50 text-red-500"}`} title={t.detail}>
                    {t.name}: {t.passed ? "OK" : "x"}
                  </span>
                ))}
              </div>
            </div>
          )}

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
        <div className="flex items-center justify-between mb-2 border-b border-gray-700 pb-2">
          <span className="text-gray-400 text-sm font-semibold">Результаты тестирования</span>
          <button
            onClick={copyLogs}
            disabled={log.length === 0}
            className="flex items-center gap-1 bg-gray-700 hover:bg-gray-800 disabled:bg-gray-500 text-white px-3 py-1 rounded text-xs font-bold transition"
            title="Скопировать все логи в буфер обмена"
          >
            <ClipboardCopy size={14} /> Копировать логи
          </button>
        </div>
        <div className="flex-1 overflow-y-auto font-mono text-sm break-all space-y-1 whitespace-pre-wrap">
          {log.length === 0 ? (
            <span className="text-gray-600">Ожидание...</span>
          ) : (
            log.map((l, i) => {
              if (l.kind === "ok") {
                return (
                  <div key={i} className="flex items-start gap-1.5 text-green-400">
                    <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
                    <span>{l.text}</span>
                  </div>
                );
              }
              if (l.kind === "fail") {
                return (
                  <div key={i} className="flex items-start gap-1.5 text-red-400">
                    <XCircle size={15} className="mt-0.5 shrink-0" />
                    <span>{l.text}</span>
                  </div>
                );
              }
              return (
                <div key={i} className={l.kind === "sys" ? "text-gray-500" : "text-blue-300"}>
                  {l.text}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
