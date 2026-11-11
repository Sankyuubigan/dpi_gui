import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Search, Globe, FileEdit, Trash2, Wrench, Square, Cookie, FolderOpen } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { useTestingLog } from "./useTestingLog";
import { OP_DNS_PICK, OP_SITE_ANALYSIS, runOp } from "../ops";
import type { SiteSolution } from "../App";

/// Вкладка «Починка сайтов»: анализ одного домена (с опциональным
/// принудительным подбором DNS-адреса) и точечная правка hosts. Тесты
/// профилей и диагностика живут на отдельной вкладке «Профили обхода».
export default function SiteFixTab({ url, setUrl, isTesting, setIsTesting, solution, setSolution, activeOp, setActiveOp }: {
  url: string;
  setUrl: Dispatch<SetStateAction<string>>;
  isTesting: boolean;
  setIsTesting: Dispatch<SetStateAction<boolean>>;
  /// Решение последнего анализа (null — анализ ещё не запускался).
  solution: SiteSolution | null;
  setSolution: Dispatch<SetStateAction<SiteSolution | null>>;
  /// Имя идущей долгой операции (src/ops.ts); кнопка «Стоп» рендерится,
  /// когда оно совпадает с операцией этой вкладки.
  activeOp: string | null;
  setActiveOp: Dispatch<SetStateAction<string | null>>;
}) {
  const [hostsIp, setHostsIp] = useState("");

  // Кукисы из браузера (PRP 08.11.26): rookie читает выбранную юзером
  // программу; значения кукисов нигде не показываются (приватность).
  const [cookieBrowsers, setCookieBrowsers] = useState<{ id: string; label: string }[]>([]);
  const [cookieBrowser, setCookieBrowser] = useState("chrome");
  const [cookieStatus, setCookieStatus] = useState<{ count: number; sources: string[]; last_browser?: string | null } | null>(null);
  // Юзер выбирал браузер в этой сессии? Тогда автодефолт из config не применяем.
  const cookieUserPickedRef = useRef(false);

  // На mount: список браузеров для select (SSOT — BROWSERS в бэкенде) и
  // текущий статус (кукисы переживают смену вкладок — хранятся в бэкенде).
  useEffect(() => {
    let alive = true;
    (async () => {
      let browsers: { id: string; label: string }[] = [];
      try {
        browsers = await invoke<{ id: string; label: string }[]>("cookies_browsers");
        if (alive) setCookieBrowsers(browsers);
      } catch {} // список статичен — ошибка не критична
      try {
        const st = await invoke<{ count: number; sources: string[]; last_browser?: string | null }>("cookies_status");
        if (!alive) return;
        setCookieStatus(st);
        // Автодефолт select из сохранённого источника (PRP 09.11.26) —
        // только пока юзер ещё не выбирал в этой сессии.
        if (!cookieUserPickedRef.current && st.last_browser && browsers.some((b) => b.id === st.last_browser)) {
          setCookieBrowser(st.last_browser);
        }
      } catch {}
    })();
    // Автозабор при старте: бэкенд эмитит cookies-updated по завершении —
    // перечитываем статус, чип появится сам (даже если вкладка уже открыта).
    const un = listen("cookies-updated", () => {
      invoke<{ count: number; sources: string[] }>("cookies_status")
        .then((st) => { if (alive) setCookieStatus(st); })
        .catch(() => {});
    });
    return () => {
      alive = false;
      un.then((f) => f()).catch(() => {});
    };
  }, []);
  // «Стоп» нажат: Err-ответ бэкенда трактуем как ожидаемую остановку,
  // а не ошибку (сам цикл здесь фронт не крутит — рулит бэкенд).
  const stopRef = useRef(false);
  const { appendEntry } = useTestingLog();

  // Кнопка «Стоп»: сигнал бэкенду остановить операцию в ближайшей
  // контрольной точке (анализ — между фазами, подбор DNS — между фазами
  // перебора; ждущие в очереди джобы анализа снимаются сразу).
  const stopCurrentOp = async () => {
    if (!activeOp) return;
    stopRef.current = true;
    appendEntry("[Стоп] Останавливаю — операция завершится в ближайшей контрольной точке...", "warn");
    try {
      await invoke("cancel_operation", { name: activeOp });
    } catch { /* сигнал отмены не важнее операции: ошибку игнорируем */ }
  };

  const runDeepAnalysis = async () => {
    if (!url) return;
    setIsTesting(true);
    stopRef.current = false;
    setSolution(null); // старое решение к новому анализу неприменимо
    // Одна стартовая строка: старт дублировался двумя FE-записями + бэкенд-дубль
    // очереди (правило «в лог не дублируем» — PRP «Читаемый лог»).
    appendEntry(`[Анализ] Запуск анализа: ${url} (до ~30 сек)...`, "info");

    try {
      // Бэкенд возвращает { report, solution }: текст отчёта уже содержит
      // блок «ИТОГ АНАЛИЗА» (те же данные, что в solution).
      const outcome: { report: string; solution: SiteSolution } = await invoke("run_domain_analysis", { url });
      // Отчёт в лог кладёт бэкенд (analyze_domain / analyze_url — SSOT);
      // здесь эхо не нужно: плагин уже разрезал отчёт на записи построчно.
      setSolution(outcome.solution ?? null);
    } catch (e: any) {
      if (stopRef.current) {
        appendEntry("[Анализ] Остановлен пользователем.", "warn");
      } else {
        appendEntry(`[Ошибка анализа]: ${e}`, "fail");
      }
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
        const kind = line.startsWith("⚠️") ? "fail" : line.startsWith("♻️") || line.startsWith("🛡️") || line.startsWith("⛔") || line.startsWith("📄") || line.startsWith("🧹") ? "ok" : "info";
        appendEntry(line, kind);
      }
    } catch (e: any) {
      appendEntry(`[Починка] Ошибка применения решения: ${e}`, "fail");
    } finally {
      setIsTesting(false);
    }
  };

  // Скрипт подбора рабочего DNS: перебор doh-services.txt. Вердикт — по
  // сквозной HTTPS-пробе (кейс Patreon 01.11.26, ownership IP не считается):
  // кто резолвит верно (адреса совпали с консенсусом), кто отдаёт собственные
  // шлюзы (фронтинг), кто расходится с большинством, кто мёртв; проба говорит,
  // открывается ли сайт через эти адреса. Независим от «Анализа сайта».
  const runDnsPick = async () => {
    const domain = cleanHost(url);
    if (!domain) {
      appendEntry("[Подбор DNS] Укажите домен в поле выше.", "fail");
      return;
    }
    setIsTesting(true);
    stopRef.current = false;
    appendEntry(`[Подбор DNS] Перебор списка DoH-сервисов для ${domain}...`, "info");
    try {
      const out = await invoke<{
        domain: string;
        entries: { service: string; resolved: string[]; kind: string; note: string; probe: string | null; probeNote: string }[];
        summary: string;
        verdictLevel: "ok" | "warn" | "fail";
      }>("pick_dns", { url: domain });
      for (const e of out.entries) {
        const mark =
          e.kind === "gateway"
            ? e.probe === "gatewayAlive" ? "🛰 СВОИ ШЛЮЗЫ (ФРОНТИНГ ПОДТВЕРЖДЁН)"
              : e.probe === "gatewayPartial" ? "🛰 СВОИ ШЛЮЗЫ (ФРОНТИНГ ЧАСТИЧНЫЙ)"
                : e.probe === "gatewayDead" ? "🛰 СВОИ ШЛЮЗЫ (ФРОНТИНГ НЕ ПОДТВЕРЖДЁН)"
                  : "🛰 СВОИ ШЛЮЗЫ (ФРОНТИНГ)"
            : e.kind === "resolves"
              ? e.probe === "unverified" ? "⚪ РЕЗОЛВИТ (доступность не подтверждена)"
                : e.probe === null ? "⚪ GeoDNS: свои адреса (консенсус невозможен, проба не выполнялась)"
                  : "✅ РЕЗОЛВИТ ВЕРНО"
              : e.kind === "diverges" ? "⚠️ РАСХОДИТСЯ С ДРУГИМИ"
                : "❌ МЁРТВ";
        const level =
          (e.kind === "resolves" && e.probe === "open") ||
            (e.kind === "gateway" && e.probe === "gatewayAlive") ? "ok"
            : e.kind === "gateway" && e.probe === "gatewayPartial" ? "warn"
              : e.kind === "dead" ||
                  (e.kind === "gateway" && e.probe === "gatewayDead") ? "fail"
                : "info";
        const probeSuffix = e.probe ? `; проба: ${e.probeNote}` : "";
        appendEntry(`${mark} — ${e.service}: ${e.note}${probeSuffix}`, level);
      }
      appendEntry(`[Подбор DNS] ${out.summary}`, out.verdictLevel);
    } catch (e: any) {
      if (stopRef.current) {
        appendEntry("[Подбор DNS] Остановлен пользователем.", "warn");
      } else {
        appendEntry(`[Подбор DNS] Ошибка: ${e}`, "fail");
      }
    } finally {
      setIsTesting(false);
    }
  };

  const cleanHost = (raw: string) =>
    raw.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];

  // Кукисы из браузера (PRP 08.11.26): из выбранного юзером браузера забираем
  // кукисы текущего домена в память бэкенда; SSOT-проба http_via_ip
  // прикрепляет Cookie-заголовок к HTTPS-пробам автоматически (browser_cookies.rs).
  const grabCookies = async (dir?: string) => {
    const domain = cleanHost(url);
    if (!domain) {
      appendEntry("[Кукисы] Укажите домен в поле выше.", "fail");
      return;
    }
    setIsTesting(true);
    try {
      const out = await invoke<{ count: number; sources: string[]; notes: string[] }>(
        "grab_cookies",
        { url: domain, browser: cookieBrowser, dir: dir ?? null }
      );
      for (const s of out.sources) appendEntry(`[Кукисы] ${s}`, "ok");
      for (const n of out.notes) appendEntry(`[Кукисы] ${n}`, "fail");
      if (out.count > 0) {
        appendEntry(`[Кукисы] Пробы теперь идут с кукисами (${out.count} шт.)`, "ok");
      }
      const st = await invoke<{ count: number; sources: string[] }>("cookies_status");
      setCookieStatus(st);
    } catch (e: any) {
      appendEntry(`[Кукисы] Ошибка захвата: ${e}`, "fail");
    } finally {
      setIsTesting(false);
    }
  };

  // Кукисы из ЛЮБОГО Chromium-браузера: юзер указывает папку User Data —
  // бэкенд сам найдёт ключ (Local State) и все кукис-базы (Default, Profile *).
  const grabFromFolder = async () => {
    const picked = await open({
      directory: true,
      multiple: false,
      title: "Укажи папку User Data браузера (например ...\\Thorium\\User Data)",
    });
    if (typeof picked !== "string" || !picked) return; // отмена
    await grabCookies(picked);
  };

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
          appendEntry("💡 Напоминание: при RST сброс идёт на уровне SNI/DPI — подмена в hosts не открывает сайт. Используйте обход (winws).", "info");
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
          Диагностика одного домена: анализ соединения, подбор рабочего
          DNS-сервера и точечная правка hosts.
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
              onClick={() => runOp(setActiveOp, OP_SITE_ANALYSIS, runDeepAnalysis)}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
            >
              <Search size={18} /> Анализ сайта / IP
            </button>
            {activeOp === OP_SITE_ANALYSIS && isTesting && (
              <button
                onClick={stopCurrentOp}
                title="Остановить анализ: завершится в ближайшей контрольной точке (между фазами проб), обход будет восстановлен"
                className="shrink-0 flex items-center justify-center gap-1.5 border-2 border-rose-300 text-rose-600 hover:bg-rose-50 px-3 py-2 rounded-lg font-bold transition"
              >
                <Square size={16} /> Стоп
              </button>
            )}
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
        </div>

        {/* «Подбор рабочего DNS» — отдельная фича, с «Анализом сайта» не связана.
            Классифицирует ответы всех DoH-сервисов (свои шлюзы / резолвит верно /
            расходится / мёртв) и проверяет сквозной HTTPS-пробой, открывается ли
            сайт через эти адреса. Кейс сессий-геоблоков (aistudio) покрыт
            универсально: шлюзы сервиса = фронтинг-кандидат. */}
        <div className="flex flex-col gap-2 mt-4 border-t border-gray-100 pt-4">
          <div className="flex gap-2">
            <button
              onClick={() => runOp(setActiveOp, OP_DNS_PICK, runDnsPick)}
              disabled={isTesting}
              className="flex-1 flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
              title="Перебирает весь список DoH-сервисов (doh-services.txt), классифицирует ответы (свои шлюзы / резолвит верно / расходится с другими / мёртв) и проверяет сквозной HTTPS-пробой, открывается ли сайт через эти адреса. Результат — имя DNS для включения в браузере (Secure DNS)."
            >
              <Globe size={18} /> Подбор DNS для обхода геоблока
            </button>
            {activeOp === OP_DNS_PICK && isTesting && (
              <button
                onClick={stopCurrentOp}
                title="Остановить подбор DNS: завершится в ближайшей контрольной точке перебора"
                className="shrink-0 flex items-center justify-center gap-1.5 border-2 border-rose-300 text-rose-600 hover:bg-rose-50 px-3 py-2 rounded-lg font-bold transition"
              >
                <Square size={16} /> Стоп
              </button>
            )}
          </div>
          {/* Кукисы из браузера: юзер выбирает браузер в select — из него
              забираем кукисы текущего домена; пробы (SSOT http_via_ip) идут
              с сессией юзера. Значения кукисов не показываем (приватность). */}
          <div className="flex gap-2 items-center px-1">
            <div className="relative shrink-0">
              <Cookie size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
              <select
                value={cookieBrowser}
                onChange={(e) => {
                  cookieUserPickedRef.current = true;
                  setCookieBrowser(e.target.value);
                }}
                className="appearance-none pl-9 pr-7 py-2 text-sm border border-gray-300 rounded-lg bg-white text-gray-700 focus:ring-2 focus:ring-emerald-500 outline-none"
                title="Из какого браузера забрать кукисы: пробы пойдут с готовой сессией юзера"
              >
                {cookieBrowsers.map((b) => (
                  <option key={b.id} value={b.id}>{b.label}</option>
                ))}
              </select>
            </div>
            <button
              onClick={() => grabCookies()}
              disabled={isTesting}
              className="shrink-0 flex items-center justify-center gap-1.5 bg-sky-600 hover:bg-sky-700 disabled:bg-gray-400 text-white py-2 px-3 rounded-lg font-semibold text-sm transition"
              title="Забрать кукисы текущего домена из выбранного браузера — пробы подбора DNS (и другие HTTPS-пробы) пойдут с готовой сессией юзера"
            >
              <Cookie size={16} /> Забрать кукисы
            </button>
            <button
              onClick={grabFromFolder}
              disabled={isTesting}
              className="shrink-0 flex items-center justify-center gap-1.5 bg-gray-100 hover:bg-gray-200 border border-gray-300 text-gray-700 disabled:bg-gray-100 py-2 px-3 rounded-lg font-semibold text-sm transition"
              title="Кукисы из ЛЮБОГО Chromium-браузера (Thorium, Яндекс и т.д.): укажи его папку User Data — ключ и все кукис-базы найдутся сами"
            >
              <FolderOpen size={16} /> Из папки…
            </button>
            {cookieStatus && cookieStatus.count > 0 && (
              <span
                className="shrink-0 flex items-center gap-1.5 bg-emerald-50 border border-emerald-200 text-emerald-700 px-3 py-2 rounded-lg font-semibold text-sm"
                title={cookieStatus.sources.join("; ") || "Кукисы в памяти"}
              >
                <Cookie size={16} /> {cookieStatus.count} кукис в памяти
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 px-1">
            Проверяет, через какой DNS-сервис сайт реально открывается (сквозная
            проба), и назовёт рабочий DNS для браузера (Secure DNS). Если дело не
            в DNS — честно скажет: TLS режет DPI (нужен обход) или сайт сам
            отказывает (гео-блок — нужен VPN).
          </p>
        </div>

        <div className="flex flex-col gap-3">
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
    </div>
  );
}
