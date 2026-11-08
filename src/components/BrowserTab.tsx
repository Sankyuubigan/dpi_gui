import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { AlertTriangle, ExternalLink, Globe, Wrench, X } from "lucide-react";
import { useTestingLog } from "./useTestingLog";

/// Статус браузера (SSOT контракта — serde BrowserStatus в browser.rs).
interface BrowserStatus {
  open: boolean;
  /// Активные привязки домен → IP (--host-resolver-rules), из config.json.
  mappings: Record<string, string>;
  /// Последний URL навигации (null — браузер ещё не открывался).
  currentUrl: string | null;
}

/// Ответ browser_apply_pick (SSOT — serde ApplyPickResult в browser.rs).
/// Отказ из-за Unverified — НЕ ошибка, а вопрос юзеру: needsForce=true
/// включает кнопку «Применить принудительно» (честное окно PRP-1).
interface ApplyPickResult {
  applied: boolean;
  needsForce: boolean;
  message: string;
}

/// Вкладка «Браузер» с ВСТРОЕННЫМ webview (08.11.26 переделка PRP-3: юзеру
/// нужен был браузер во вкладке, не отдельным окном). Webview — нативный child
/// главного окна (Window::add_child, browser.rs): он рисуется ПОВЕРХ HTML,
/// контейнер ниже лишь резервирует его место (getBoundingClientRect →
/// browser_set_bounds). Свой профиль WebView2 (логины переживают пересоздание),
/// инжект ПКМ-меню, подмена адресов через host-resolver-rules.
export default function BrowserTab() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<BrowserStatus | null>(null);
  const [dohList, setDohList] = useState<string[] | null>(null);
  const [dohError, setDohError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Вопрос юзеру после отказа Unverified: текст пояснения + кнопка
  // «Применить принудительно» (force-повтор). null — вопроса нет.
  const [forceAsk, setForceAsk] = useState<string | null>(null);
  const { appendEntry } = useTestingLog();
  // Контейнер, под который выравнивается embedded webview (см. док-коммент).
  const containerRef = useRef<HTMLDivElement | null>(null);
  // Таймер дебаунса bounds-синхронизации (~50 мс) — browser_set_bounds не
  // должен сыпаться на каждый пиксель resize/scroll.
  const boundsTimer = useRef<number | null>(null);

  // Текущие границы контейнера в логических px относительно окна — ровно то,
  // что ждут LogicalPosition/LogicalSize в add_child/set_bounds (шаг 0).
  const readBounds = (): [number, number, number, number] | null => {
    const el = containerRef.current;
    if (!el) return null;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return null;
    return [r.left, r.top, r.width, r.height];
  };

  const syncBounds = () => {
    const b = readBounds();
    if (!b) return;
    invoke("browser_set_bounds", { x: b[0], y: b[1], w: b[2], h: b[3] }).catch(() => {});
  };

  const syncBoundsDebounced = () => {
    if (boundsTimer.current !== null) window.clearTimeout(boundsTimer.current);
    boundsTimer.current = window.setTimeout(syncBounds, 50);
  };

  // Статус: браузер могут закрыть командой мимо вкладки — опрашиваем раз в 2 с,
  // чтобы индикатор не лгал «открыто» на мёртвом webview.
  const refreshStatus = async () => {
    try {
      setStatus(await invoke<BrowserStatus>("browser_status"));
    } catch { /* статус некритичен — следующая итерация попробует снова */ }
  };

  useEffect(() => {
    // Вход на вкладку: показать webview (если открыт) и выровнять по контейнеру.
    invoke("browser_show").catch(() => {});
    syncBounds();

    const ro = new ResizeObserver(syncBoundsDebounced);
    if (containerRef.current) ro.observe(containerRef.current);
    window.addEventListener("resize", syncBoundsDebounced);
    // Скролл страницы двигает контейнер: событие scroll не всплывает —
    // ловим на document в capture-фазе.
    const onScroll = () => syncBoundsDebounced();
    document.addEventListener("scroll", onScroll, true);

    refreshStatus();
    invoke<string[]>("get_doh_services")
      .then((hs) => { setDohList(hs); setDohError(null); })
      .catch((e) => setDohError(String(e)));
    // Адресная строка следует за браузером: бэкенд шлёт "browser-url" на каждый
    // переход (on_navigation), включая chrome-error:// при неудачной загрузке.
    const unUrl = listen<string>("browser-url", (ev) => setUrl(ev.payload));
    const poll = setInterval(refreshStatus, 2000);
    return () => {
      // Уход со вкладки: webview скрывается (страница и профиль живут в фоне).
      invoke("browser_hide").catch(() => {});
      ro.disconnect();
      window.removeEventListener("resize", syncBoundsDebounced);
      document.removeEventListener("scroll", onScroll, true);
      unUrl.then((f) => f());
      clearInterval(poll);
    };
  }, []);

  const openBrowser = async () => {
    if (!url.trim()) {
      appendEntry("[Браузер] Укажите адрес сайта.", "fail");
      return;
    }
    setBusy(true);
    appendEntry(`[Браузер] Открываю ${url.trim()} во вкладке...`, "info");
    try {
      const bounds = readBounds();
      const msg: string = await invoke(
        "browser_open",
        bounds ? { url: url.trim(), bounds } : { url: url.trim() },
      );
      appendEntry(`[Браузер] ${msg}`, "ok");
    } catch (e) {
      appendEntry(`[Браузер] Ошибка открытия: ${e}`, "fail");
    } finally {
      setBusy(false);
      refreshStatus();
    }
  };

  const closeBrowser = async () => {
    setBusy(true);
    try {
      await invoke("browser_close");
      appendEntry("[Браузер] Браузер закрыт (профиль с логинами сохранён).", "info");
    } catch (e) {
      appendEntry(`[Браузер] Ошибка закрытия: ${e}`, "fail");
    } finally {
      setBusy(false);
      refreshStatus();
    }
  };

  // Применение результата «Подбора DNS» (SSOT: LAST_PICK на бэкенде).
  // force=false — первый проход; отказ Unverified приходит как needsForce
  // (вопрос юзеру, не исключение) и включает «Применить принудительно».
  const applyPick = async (force: boolean) => {
    setBusy(true);
    try {
      const res: ApplyPickResult = await invoke("browser_apply_pick", { force });
      if (res.applied) {
        appendEntry(`[Браузер] ${res.message}`, "ok");
        setForceAsk(null);
      } else if (res.needsForce) {
        setForceAsk(res.message);
        appendEntry(`[Браузер] ${res.message}`, "warn");
      } else {
        appendEntry(`[Браузер] ${res.message}`, "fail");
        setForceAsk(null);
      }
    } catch (e) {
      appendEntry(`[Браузер] Ошибка применения: ${e}`, "fail");
    } finally {
      setBusy(false);
      refreshStatus();
    }
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 className="text-xl font-bold text-gray-800 mb-1">Браузер</h2>
        <p className="text-gray-500 mb-4 text-sm">
          Встроенный браузер прямо на этой вкладке: свой профиль — логины
          сохраняются между запусками и не теряются при пересоздании после
          подбора DNS. Правая кнопка мыши по ссылке — «Подбор DNS для обхода
          геоблока» и «Открыть в системном браузере».
        </p>

        {/* Статус + активные привязки (честность: живой опрос, не кэш) */}
        <div className="flex items-center flex-wrap gap-2 mb-4 text-sm">
          <span className={status?.open ? "text-green-600 font-bold" : "text-gray-400"}>
            {status?.open ? "● Браузер открыт" : "○ Браузер закрыт"}
          </span>
          {status && Object.entries(status.mappings).map(([d, ip]) => (
            <span
              key={d}
              className="bg-cyan-50 text-cyan-800 border border-cyan-200 rounded px-2 py-0.5 text-xs font-mono"
              title="Домен привязан к IP через --host-resolver-rules (браузер во вкладке)"
            >
              {d} → {ip}
            </span>
          ))}
        </div>

        {/* Адресная строка */}
        <div className="flex gap-2 mb-4">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-3 text-gray-400" size={20} />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") openBrowser(); }}
              placeholder="Адрес сайта (например, aistudio.google.com)"
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
            />
          </div>
          <button
            onClick={openBrowser}
            disabled={busy}
            className="flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white py-2 px-4 rounded-lg font-bold transition"
            title="Открыть адрес во встроенном браузере вкладки (свой профиль)"
          >
            <ExternalLink size={18} /> Открыть
          </button>
          <button
            onClick={closeBrowser}
            disabled={busy || !status?.open}
            className="flex items-center justify-center gap-2 bg-gray-200 hover:bg-gray-300 disabled:bg-gray-100 disabled:text-gray-400 text-gray-700 py-2 px-4 rounded-lg font-bold transition"
            title="Закрыть встроенный браузер (профиль с логинами сохранится)"
          >
            <X size={18} /> Закрыть
          </button>
        </div>

        {/* Зона встроенного webview: нативный child рисуется ПОВЕРХ этого
            блока (bounds шлёт useEffect ниже); пока браузер закрыт —
            заглушка-подсказка, при открытии её накрывает webview. */}
        <div
          ref={containerRef}
          className="relative w-full bg-gray-900 rounded-lg border border-gray-300 overflow-hidden"
          style={{ height: 460 }}
        >
          {!status?.open && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-400 text-sm px-6 text-center gap-1">
              <Globe size={36} className="opacity-50" />
              <p className="font-semibold text-gray-300">Браузер закрыт</p>
              <p className="text-xs max-w-md">
                Введите адрес выше и нажмите «Открыть» — сайт появится прямо
                здесь, внутри вкладки. Уход с вкладки его скрывает, возврат —
                показывает снова.
              </p>
            </div>
          )}
        </div>

        {/* Применение результата подбора DNS */}
        <div className="border-t border-gray-100 pt-4 mt-4 flex flex-col gap-2">
          <p className="text-xs text-gray-500">
            Если «Подбор DNS» нашёл рабочий адрес (вкладка «Починка сайтов» или
            ПКМ на странице браузера) — примените его: домен привяжется к адресу
            через подмену DNS-ответа, браузер во вкладке пересоздастся, логины
            сохранятся.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => applyPick(false)}
              disabled={busy}
              className="flex-1 flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-400 text-white py-2 rounded-lg font-bold transition"
              title="Привязать домен к адресу из последнего «Подбора DNS» (проба «открывается» или живой шлюз)"
            >
              <Wrench size={18} /> Применить результат подбора
            </button>
            {forceAsk && (
              <button
                onClick={() => applyPick(true)}
                disabled={busy}
                className="flex items-center justify-center gap-2 border-2 border-amber-400 text-amber-700 bg-amber-50 hover:bg-amber-100 px-3 py-2 rounded-lg font-bold transition"
                title="Юзер подтверждает: применить адрес с непроверенной доступностью (JS-оболочка)"
              >
                <AlertTriangle size={18} /> Применить принудительно
              </button>
            )}
          </div>
          <p className="text-xs text-gray-400">
            Подмена адреса не обходит DPI: если провайдер режет SNI домена, сайт
            не откроется и с рабочим DNS — тогда нужен обход (winws). Проба
            «JS-оболочка» (⚪ в подборе) — транспорт работает, но доступность
            после входа в аккаунт не подтверждена: принудительное применение —
            осознанный риск.
          </p>
        </div>

        {/* DoH-сервисы: альтернатива привязке — Secure DNS браузера */}
        <div className="border-t border-gray-100 pt-4 mt-4">
          <p className="text-xs font-semibold text-gray-600 mb-1">
            DoH-сервисы (doh-services.txt) — альтернатива привязке: включить
            один из них как Secure DNS в настройках браузера:
          </p>
          {dohError ? (
            <p className="text-xs text-red-500 font-mono break-all">{dohError}</p>
          ) : (
            <p className="text-xs text-gray-500 font-mono break-all">
              {dohList === null ? "Загрузка..." : dohList.length ? dohList.join(" · ") : "Список пуст — добавьте сервисы в Настройках"}
            </p>
          )}
        </div>
      </div>

    </div>
  );
}
