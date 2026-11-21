import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Router } from "lucide-react";

/// «Маршрутизатор» (Этап A 19.11.26): режимы групп доменов + системный
/// PAC-подхват браузеров. Домены живут в «Управлении списками» (SSOT — там);
/// здесь только переключатели (routing.json). Бэкенд — pac_server.rs/routing.rs.
export default function RoutingCard() {
  const [st, setSt] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const reload = useCallback(async () => {
    try {
      setSt(await invoke("routing_status"));
    } catch (e) {
      console.error("routing_status:", e);
      setSt(null);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const setMode = async (field: string, value: string) => {
    if (!st) return;
    setBusy(true);
    setMsg(null);
    try {
      const r: string = await invoke("routing_set_mode", {
        dpiMode: field === "dpi" ? value : st.dpi_mode,
        geoMode: field === "geo" ? value : st.geo_mode,
        routeMode: field === "route" ? value : st.route_mode,
      });
      setMsg({ ok: true, text: r });
    } catch (e: any) {
      // Честный catch (урок 18.11: молчаливый catch прячет ACL-отказ).
      setMsg({ ok: false, text: String(e) });
    }
    await reload();
    setBusy(false);
  };

  const setPac = async (enabled: boolean) => {
    setBusy(true);
    setMsg(null);
    try {
      const r: string = await invoke("pac_set", { enabled });
      setMsg({ ok: true, text: r });
    } catch (e: any) {
      setMsg({ ok: false, text: String(e) });
    }
    await reload();
    setBusy(false);
  };

  return (
    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
      <div className="flex items-center gap-2 mb-1">
        <Router size={18} className="text-blue-600" />
        <h2 className="text-xl font-bold text-gray-800">Маршрутизатор</h2>
      </div>
      <p className="text-gray-500 mb-4 text-sm">
        Куда идёт каждая группа доменов: через обход (winws), через канал (прокси
        127.0.0.1:7897) или напрямую. Домены — в «Управлении списками»: dpi-группа —
        General List, гео-группа — Geo List, исключения (банки и т.п.) — всегда напрямую.
      </p>

      {!st ? (
        <p className="text-gray-500 text-sm">Статус маршрутизации недоступен (смотри лог).</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              dpi-группа (YouTube, список обхода) — {st.dpi_count} дом.
            </label>
            <select
              value={st.dpi_mode}
              disabled={busy}
              onChange={(e) => setMode("dpi", e.target.value)}
              className="w-full border-gray-300 rounded-md shadow-sm p-2 border focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="winws">Обход winws (по умолчанию)</option>
              <option value="channel">Через канал</option>
              <option value="direct">Напрямую, без обхода</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              гео-группа (aistudio, Adobe) — {st.geo_count} дом.
            </label>
            <select
              value={st.geo_mode}
              disabled={busy}
              onChange={(e) => setMode("geo", e.target.value)}
              className="w-full border-gray-300 rounded-md shadow-sm p-2 border focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="channel">Через канал</option>
              <option value="direct">Напрямую</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Канал</label>
            <select
              value={st.route_mode}
              disabled={busy}
              onChange={(e) => setMode("route", e.target.value)}
              className="w-full border-gray-300 rounded-md shadow-sm p-2 border focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="selective">Селективно: через канал только домены групп</option>
              <option value="fullport">Весь трафик через канал</option>
            </select>
          </div>
        </div>
      )}

      <label className="flex items-start gap-3 mt-4 cursor-pointer">
        <input
          type="checkbox"
          checked={Boolean(st?.pac_on)}
          disabled={busy || !st}
          onChange={(e) => setPac(e.target.checked)}
          className="mt-0.5 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
        />
        <span>
          <span className="block text-sm font-medium text-gray-700">
            Подхват браузеров (PAC) — системная настройка
          </span>
          <span className="block text-xs text-gray-500">
            Браузеры без расширений сами направят домены групп «канал» на прокси
            {st?.proxy_port ? ` 127.0.0.1:${st.proxy_port}` : ""}, остальное — напрямую.
            Канал должен быть включён, иначе браузеры честно пойдут напрямую.
            Смена режимов применяется сразу (кроме dpi при активном обходе — он
            подхватится при следующем запуске обхода).
          </span>
        </span>
      </label>

      {/* Честные ограничения — софт не врёт, что PAC всё чинит */}
      <div className="mt-3 text-xs text-gray-500 space-y-1">
        <p>
          • Telegram Desktop PAC не читает: чтобы Telegram шёл через канал — укажи
          SOCKS5/HTTP 127.0.0.1:7897 вручную (Настройки → Продвинутые → Соединение).
        </p>
        <p>
          • Голос Discord и Telegram-звонки — UDP: через прокси идёт только на нодах
          с udp-поддержкой; обычно голос живёт на обходе (winws).
        </p>
      </div>

      {msg && (
        <p className={"mt-3 text-sm " + (msg.ok ? "text-green-700" : "text-red-600")}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
