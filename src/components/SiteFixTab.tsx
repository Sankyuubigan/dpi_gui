import { useState, type Dispatch, type SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Search, Globe, ShieldQuestion, FileEdit, Trash2, Wrench } from "lucide-react";
import TestingLogPanel, { type LogEntry } from "./TestingLogPanel";
import { useTestingLog } from "./useTestingLog";
import type { SiteSolution } from "../App";

/// Вкладка «Починка сайтов»: анализ одного домена, тест подмены DNS по
/// всему списку DoH и точечная правка hosts. Тесты профилей и диагностика
/// живут на отдельной вкладке «Профили обхода».
export default function SiteFixTab({ log, setLog, url, setUrl, isTesting, setIsTesting, solution, setSolution }: {
  log: LogEntry[];
  setLog: Dispatch<SetStateAction<LogEntry[]>>;
  url: string;
  setUrl: Dispatch<SetStateAction<string>>;
  isTesting: boolean;
  setIsTesting: Dispatch<SetStateAction<boolean>>;
  /// Решение последнего анализа (null — анализ ещё не запускался).
  solution: SiteSolution | null;
  setSolution: Dispatch<SetStateAction<SiteSolution | null>>;
}) {
  const [hostsIp, setHostsIp] = useState("");
  const { appendEntry, appendLog } = useTestingLog(setLog);

  const runDeepAnalysis = async () => {
    if (!url) return;
    setIsTesting(true);
    setSolution(null); // старое решение к новому анализу неприменимо
    setLog([
      { text: `[Анализ] Запуск анализа для: ${url}...`, kind: "info" },
      { text: "Идёт анализ: пробы соединения (с обходом/без), поиск кандидатов в списках (до ~30 сек)...", kind: "info" }
    ]);

    try {
      // Бэкенд возвращает { report, solution }: текст отчёта уже содержит
      // блок «ИТОГ АНАЛИЗА» (те же данные, что в solution).
      const outcome: { report: string; solution: SiteSolution } = await invoke("run_domain_analysis", { url });
      appendLog(outcome.report);
      setSolution(outcome.solution ?? null);
    } catch (e: any) {
      appendLog(`[Ошибка анализа]: ${e}`);
    } finally {
      setIsTesting(false);
    }
  };

  // «Починить сайт»: применяет найденное решение (списки обхода/исключений,
  // hosts). Активна только когда анализ реально нашёл решение.
  const applySolution = async () => {
    if (!solution?.found) return;
    setIsTesting(true);
    appendEntry(`[Починка] Применяю найденное решение: ${solution.summary}...`, "info");
    try {
      const result: string = await invoke("apply_solution", { solution });
      for (const line of result.split("\n")) {
        const kind = line.startsWith("⚠️") ? "fail" : line.startsWith("♻️") || line.startsWith("🛡️") || line.startsWith("⛔") || line.startsWith("📄") ? "ok" : "info";
        appendEntry(line, kind);
      }
    } catch (e: any) {
      appendEntry(`[Починка] Ошибка применения решения: ${e}`, "fail");
    } finally {
      setIsTesting(false);
    }
  };

  // «Тест подмены DNS» прогоняет ВЕСЬ список DoH-сервисов (lists/defaults/
  // doh-services.txt) по очереди для одного домена. Список читается при
  // каждом запуске — свежие правки файла применяются без перезапуска.
  const runDnsTest = async () => {
    if (!url) return;
    setIsTesting(true);
    setLog([{ text: `[Тест DNS] Проверка сайта ${url} через список DoH-сервисов...`, kind: "info" }]);

    let services: string[] = [];
    try {
      services = await invoke<string[]>("get_doh_services");
    } catch (e: any) {
      appendEntry(`[Тест DNS] Не удалось получить список DoH-сервисов: ${e}`, "fail");
      setIsTesting(false);
      return;
    }

    if (services.length === 0) {
      appendEntry("[Тест DNS] Список DoH-сервисов пуст.", "fail");
      setIsTesting(false);
      return;
    }

    appendEntry(`Сервисов в списке: ${services.length}. Прогон по очереди...`, "info");
    let okCount = 0;
    let partialCount = 0;
    for (const svc of services) {
      try {
        const result: string = await invoke("test_dns", { url, dnsIp: svc });
        const flat = result.replace(/\s*\n\s*/g, " · ");
        if (result.startsWith("УСПЕХ")) {
          okCount++;
          appendEntry(`   ${svc} — ${flat}`, "ok");
        } else if (result.startsWith("ОШИБКА")) {
          appendEntry(`   ${svc} — ${flat}`, "fail");
        } else {
          // «Доступно, но статус: ...» — DNS и соединение работают, ответ не 2xx.
          partialCount++;
          appendEntry(`   ${svc} — ${flat}`, "info");
        }
      } catch (e: any) {
        appendEntry(`   ${svc} — ошибка: ${e}`, "fail");
      }
    }
    const failed = services.length - okCount - partialCount;
    appendEntry(
      `[Тест DNS] Итог: успех ${okCount}, частично ${partialCount}, неудач ${failed} из ${services.length}.`,
      okCount > 0 ? "ok" : "fail"
    );
    setIsTesting(false);
  };

  const cleanHost = (raw: string) =>
    raw.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];

  const applyHosts = async () => {
    const domain = cleanHost(url);
    if (!domain || !hostsIp.trim()) {
      appendEntry("[hosts] Укажите домен и IP-адрес для записи в hosts.", "fail");
      return;
    }
    setIsTesting(true);
    appendEntry(`[hosts] Запись в hosts: ${hostsIp.trim()} → ${domain}...`, "info");
    try {
      const msg: string = await invoke("apply_hosts_entry", {
        ip: hostsIp.trim(),
        domain,
      });
      appendEntry(msg, "ok");

      appendEntry(`[hosts] Проверка HTTPS: открывается ли ${domain} через ${hostsIp.trim()}...`, "info");
      try {
        const verify: string = await invoke("verify_site_via_ip", {
          host: domain,
          ip: hostsIp.trim(),
        });
        const isOk = verify.includes("✅");
        const isRst = verify.includes("RST");
        appendEntry(
          verify,
          isOk ? "ok" : isRst ? "fail" : "info"
        );
        if (isRst) {
          appendLog("💡 Напоминание: при RST сброс идёт на уровне SNI/DPI — подмена в hosts не открывает сайт. Используйте обход (winws).");
        }
      } catch (err: any) {
        appendEntry(`[hosts] Ошибка авто-проверки: ${err}`, "fail");
      }
    } catch (e: any) {
      appendEntry(`[hosts] Ошибка записи: ${e}`, "fail");
    } finally {
      setIsTesting(false);
    }
  };

  const removeHosts = async () => {
    const domain = cleanHost(url);
    if (!domain) {
      appendEntry("[hosts] Укажите домен для удаления из hosts.", "fail");
      return;
    }
    setIsTesting(true);
    try {
      const msg: string = await invoke("remove_hosts_entry", { domain });
      appendEntry(msg, "info");
    } catch (e: any) {
      appendEntry(`[hosts] Ошибка удаления: ${e}`, "fail");
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 className="text-xl font-bold text-gray-800 mb-4">Починка сайтов</h2>
        <p className="text-gray-500 mb-4 text-sm">
          Диагностика одного домена: анализ соединения, тест подмены DNS по всему
          списку DoH и точечная правка hosts.
        </p>

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
              <Search size={18} /> Анализ сайта / IP
            </button>
          </div>

          {/* Кнопка «Починить сайт»: активна ТОЛЬКО когда анализ нашёл решение.
              Текст-подсказка объясняет, почему кнопка неактивна. */}
          <div className="flex gap-3">
            <button
              onClick={applySolution}
              disabled={isTesting || !solution?.found}
              className="flex-1 flex items-center justify-center gap-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-200 disabled:text-gray-400 text-white py-2 rounded-lg font-bold transition"
              title={
                solution?.found
                  ? `Применить решение: ${solution.summary}`
                  : "Сначала запустите «Анализ сайта / IP» — кнопка активируется, если для сайта найдено решение"
              }
            >
              <Wrench size={18} /> Починить сайт
            </button>
          </div>
          {solution && !solution.found && solution.noneReason && (
            <p className="text-xs text-gray-500 -mt-1 px-1">
              Решение не найдено: {solution.noneReason}
            </p>
          )}
          {solution?.found && (
            <p className="text-xs text-green-700 -mt-1 px-1">
              Будет применено: {solution.summary}
            </p>
          )}

          <div className="flex gap-3 mt-2 border-t border-gray-100 pt-4">
            <button
              onClick={runDnsTest}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
              title="Прогоняет весь список DoH-сервисов (файл doh-services.txt) по очереди для этого домена"
            >
              <ShieldQuestion size={18} /> Тест подмены DNS (весь список DoH)
            </button>
          </div>

          <div className="flex gap-2 mt-2 items-center border-t border-gray-100 pt-4">
            <input
              type="text"
              value={hostsIp}
              onChange={(e) => setHostsIp(e.target.value)}
              placeholder="IP для hosts (например 185.110.92.48)"
              className="w-1/3 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-cyan-500 outline-none text-sm"
              title="IP-адрес, который нужно прописать в hosts для домена выше"
            />
            <button
              onClick={applyHosts}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-1.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-400 text-white py-2 px-3 rounded-lg font-bold text-sm transition"
              title="Записать строку 'IP домен' в C:\Windows\System32\drivers\etc\hosts и проверить HTTPS"
            >
              <FileEdit size={16} /> В hosts + тест
            </button>
            <button
              onClick={removeHosts}
              disabled={isTesting}
              className="flex items-center justify-center gap-1.5 bg-gray-200 hover:bg-gray-300 disabled:bg-gray-100 text-gray-700 py-2 px-3 rounded-lg font-semibold text-sm transition"
              title="Удалить записи DPI_GUI для этого домена из hosts"
            >
              <Trash2 size={16} /> Убрать
            </button>
          </div>
        </div>
      </div>

      <TestingLogPanel log={log} setLog={setLog} />
    </div>
  );
}
