import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Globe, Plus, Trash2, FileUp, KeyRound, RotateCcw, Loader2, CheckCircle2,
} from "lucide-react";

/// Вкладка «Канал» (PRP 18.11.26, редизайн по требованию юзера): селектор
/// каналов строится ИЗ РЕЕСТРА юзера (никаких хардкод-режимов «Платный»/
/// «Запасной» — имя каждого канала задаёт сам юзер при добавлении). Личное
/// (подписки, ключи WireGuard) живёт только в AppData этого юзера.
export default function ChannelTab({
  logMsg,
}: {
  logMsg: (msg: string) => void;
}) {
  // Реестр каналов юзера (paid_profiles.json): записи {name, file, type, ...},
  // где file — id канала (имя yaml-файла или «__wg__» для WireGuard).
  const [registry, setRegistry] = useState<any>({ profiles: [], active: "" });
  // Состояние канала: опрос каждые 3с — статус должен быстро и честно
  // переврать (мёртвый процесс ≠ зелёный бейдж, §2.2).
  const [channel, setChannel] = useState<any>(null);
  const [channelBusy, setChannelBusy] = useState(false);
  const [fixBusy, setFixBusy] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  // WG-креды (статус без приватного ключа).
  const [creds, setCreds] = useState<any>({ present: false });

  // Inline-ввод имени: после файл-диалога юзер сам называет канал
  // (требование юзера 18.11.26 — имя не автостем, а его слово).
  const [pendingAdd, setPendingAdd] = useState<{ path: string; name: string } | null>(null);
  const [pendingWg, setPendingWg] = useState<{ path: string; name: string } | null>(null);

  // Честные catch: фейл опроса логируется ОДИН раз при переходе в ошибку
  // (poll 3с — спамить лог каждую секунду нельзя, но и глотать нельзя).
  const statusErrRef = useRef(false);

  useEffect(() => {
    let stop = false;
    const poll = () => {
      invoke("channel_status")
        .then((s) => {
          if (!stop) {
            setChannel(s);
            if (statusErrRef.current) statusErrRef.current = false;
          }
        })
        .catch((e: any) => {
          if (!stop) {
            setChannel(null);
            if (!statusErrRef.current) {
              statusErrRef.current = true;
              logMsg(`Канал: статус недоступен: ${e}`);
            }
          }
        });
    };
    poll();
    const t = setInterval(poll, 3000);
    return () => { stop = true; clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refreshRegistry = () => {
    invoke("paid_profiles_list")
      .then(setRegistry)
      .catch((e: any) => logMsg(`Канал: список каналов недоступен: ${e}`));
    invoke("wg_creds_status")
      .then(setCreds)
      .catch((e: any) => logMsg(`Канал: статус WG-кредов недоступен: ${e}`));
  };
  useEffect(refreshRegistry, []);
  // eslint-disable-next-line react-hooks/exhaustive-deps

  // Имя канала по id — для логов и статуса (id «__wg__»/файла → слово юзера).
  const nameFor = (id: string) =>
    id === "off"
      ? "Выкл"
      : ((registry.profiles || []).find((p: any) => p.file === id)?.name || id);

  const setChannelMode = async (mode: string) => {
    if (channelBusy) return;
    setChannelBusy(true);
    logMsg(`Канал: переключаю на «${nameFor(mode)}»...`);
    try {
      const r: string = await invoke("channel_set", { mode });
      logMsg(`Канал: ${r}`);
    } catch (e: any) {
      logMsg(`Канал: ошибка переключения: ${e}`);
    } finally {
      setChannelBusy(false);
      invoke("channel_status").then(setChannel).catch(() => {});
    }
  };

  // «Починить систему» (красный баннер перехвата): гасим чужие перехватчики,
  // снимаем их fake-ip маршруты (198.18.0.0/15), сбрасываем DNS-кэш Windows
  // — отчёт построчно в лог (инцидент 19.11.26: весь трафик стоял в чужом
  // fake-ip TUN, а софт обязан это видеть и уметь чинить).
  const fixSystem = async () => {
    if (fixBusy) return;
    setFixBusy(true);
    logMsg("Канал: чиню систему (чужой fake-ip-перехват)...");
    try {
      const report: string[] = await invoke("channel_fix_system");
      for (const line of report) logMsg(`Канал: ${line}`);
    } catch (e: any) {
      logMsg(`Канал: ошибка починки: ${e}`);
    } finally {
      setFixBusy(false);
      invoke("channel_status").then(setChannel).catch(() => {});
    }
  };

  // Стем файла для префилла имени (C:\...\proton.yaml → «proton»).
  const stemOf = (path: string) =>
    path.split(/[\\/]/).pop()?.replace(/\.[^.]*$/, "") || "";

  // ==== Добавление yaml-канала: файл-диалог → имя юзера → регистрация ====
  const addChannelPick = async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: "Профиль mihomo/clash (YAML)", extensions: ["yaml", "yml"] }],
    });
    if (!path) return;
    setPendingAdd({ path: String(path), name: stemOf(String(path)) });
  };

  const addChannelConfirm = async () => {
    if (!pendingAdd || listBusy) return;
    setListBusy(true);
    logMsg(`Канал: добавляю «${pendingAdd.name.trim() || pendingAdd.path}»...`);
    try {
      const reg: any = await invoke("paid_profile_add", {
        path: pendingAdd.path,
        name: pendingAdd.name,
      });
      setRegistry(reg);
      logMsg("Канал: добавлен.");
      setPendingAdd(null);
    } catch (e: any) {
      logMsg(`Канал: не добавить канал: ${e}`);
    } finally {
      setListBusy(false);
    }
  };

  // ==== Импорт WG .conf: файл-диалог → имя юзера → креды + запись в реестре ====
  const importWgPick = async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: "WireGuard конфигурация", extensions: ["conf"] }],
    });
    if (!path) return;
    setPendingWg({ path: String(path), name: stemOf(String(path)) });
  };

  const importWgConfirm = async () => {
    if (!pendingWg || listBusy) return;
    setListBusy(true);
    logMsg("Канал: импортирую WireGuard .conf...");
    try {
      const s: any = await invoke("wg_creds_import", {
        path: pendingWg.path,
        name: pendingWg.name,
      });
      setCreds(s);
      refreshRegistry(); // wg_channel_sync изменил реестр — перечитать
      logMsg(`Канал: креды импортированы (${s.endpoint}).`);
      setPendingWg(null);
    } catch (e: any) {
      logMsg(`Канал: не импортировать .conf: ${e}`);
    } finally {
      setListBusy(false);
    }
  };

  // Удаление из списка: yaml — файл+запись; WG-запись удаляется только
  // вместе с кредами («Сбросить») — иначе импорт вернул бы её молча.
  const deleteEntry = async (p: any) => {
    if (listBusy) return;
    if (p.type === "wg" || p.file === "__wg__") {
      if (!confirm(`Сбросить WireGuard-креды и убрать «${p.name}» из каналов? Включить WG снова можно будет только после импорта .conf.`)) return;
      setListBusy(true);
      try {
        await invoke("wg_creds_reset");
        setCreds({ present: false });
        refreshRegistry();
        logMsg(`Канал: WG-креды сброшены, «${p.name}» убран из списка.`);
      } catch (e: any) {
        logMsg(`Канал: не сбросить креды: ${e}`);
      } finally {
        setListBusy(false);
      }
      return;
    }
    if (!confirm(`Удалить канал «${p.name}» из списка? Файл профиля будет удалён с диска.`)) return;
    setListBusy(true);
    try {
      const reg: any = await invoke("paid_profile_delete", { fileId: p.file });
      setRegistry(reg);
      logMsg(`Канал: «${p.name}» удалён.`);
    } catch (e: any) {
      logMsg(`Канал: не удалить канал: ${e}`);
    } finally {
      setListBusy(false);
    }
  };

  const kb = (n: any) => {
    const v = Number(n) || 0;
    return v >= 1024 * 1024 ? `${(v / 1024 / 1024).toFixed(1)} МБ` : `${Math.max(1, Math.round(v / 1024))} КБ`;
  };

  // added_ts (unix-секунды, новые записи) → локальное время юзера; старые
  // записи (строка из миграции) показываем как есть.
  const fmtAdded = (p: any) =>
    typeof p.added_ts === "number" && p.added_ts > 0
      ? new Date(p.added_ts * 1000).toLocaleString([], {
          day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit",
        })
      : p.added;

  const entries: any[] = registry.profiles || [];
  const hasCreds = Boolean(creds?.present);
  const mode = channel?.mode || "off";

  return (
    <div className="flex flex-col gap-4">
      {/* ИНТЕРНЕТ-КАНАЛ: proxy-only движок mihomo. Селектор = каналы юзера
          из реестра (имя каждого — слово юзера) + «Выкл». Программы ходят
          через 127.0.0.1:7897 сами (браузер — через расширение). */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Globe size={18} className="text-sky-500" />
            <h3 className="font-bold text-gray-800">Интернет-канал (прокси 127.0.0.1:7897)</h3>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setChannelMode("off")}
              disabled={channelBusy}
              title="Полностью выключить прокси-канал (процесс mihomo будет остановлен)"
              className={
                "px-4 py-2 rounded-md font-bold text-sm transition-colors border " +
                (channelBusy
                  ? "border-gray-200 text-gray-400 cursor-not-allowed"
                  : mode === "off"
                    ? "border-gray-400 bg-gray-100 text-gray-700"
                    : "border-gray-300 text-gray-600 hover:bg-gray-50")
              }
            >
              Выкл
            </button>
            {entries.map((p) => {
              const active = mode === p.file;
              const locked = p.type === "wg" && !hasCreds;
              return (
                <button
                  key={p.file}
                  onClick={() => setChannelMode(p.file)}
                  disabled={channelBusy || locked}
                  title={
                    p.type === "wg"
                      ? hasCreds
                        ? "WireGuard-канал юзера через один mihomo (гард самолечения)"
                        : "Нет WireGuard-кредов — импортируй .conf в списке ниже"
                      : `Переключить канал на «${p.name}» (yaml-профиль)`
                  }
                  className={
                    "px-4 py-2 rounded-md font-bold text-sm transition-colors border " +
                    ((channelBusy || locked)
                      ? "border-gray-200 text-gray-400 cursor-not-allowed"
                      : active
                        ? p.type === "wg"
                          ? "border-emerald-500 bg-emerald-500 text-white"
                          : "border-sky-500 bg-sky-500 text-white"
                        : "border-gray-300 text-gray-600 hover:bg-gray-50")
                  }
                >
                  {p.name}
                </button>
              );
            })}
          </div>
        </div>
        <div className="mt-3 text-sm flex items-center gap-2 flex-wrap">
          {channelBusy ? (
            <>
              <Loader2 size={14} className="animate-spin text-gray-500" />
              <span className="text-gray-500">переключаю…</span>
            </>
          ) : !channel ? (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-gray-400 inline-block" />
              <span className="text-gray-500">статус недоступен (смотри лог)</span>
            </>
          ) : (mode !== "off" && !channel.running) ? (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
              <span className="text-amber-700 font-semibold">
                ПРОЦЕСС МЁРТВ (канал «{nameFor(mode)}») — включи канал заново
              </span>
            </>
          ) : channel.running ? (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />
              <span className="text-green-700 font-semibold">
                КАНАЛ «{nameFor(mode)}» — порт жив
              </span>
              {mode === "__wg__" && (
                <span className="text-gray-600">
                  — выход: <b>{(channel.reserve?.exit_cc || "?").toUpperCase()}</b>
                  {channel.reserve?.node && (
                    <span className="text-gray-500" title={channel.reserve.node}>
                      {" "}· нода: {String(channel.reserve.node).slice(0, 40)}
                    </span>
                  )}
                  {typeof channel.reserve?.heals === "number" && channel.reserve.heals > 0 && (
                    <span className="text-gray-500"> · самолечений: {channel.reserve.heals}</span>
                  )}
                  {channel.reserve?.last_error && (
                    <span className="text-red-600" title={channel.reserve.last_error}>
                      {" "}· ошибка: {channel.reserve.last_error}
                    </span>
                  )}
                </span>
              )}
            </>
          ) : (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
              <span className="text-red-600 font-semibold">ВЫКЛЮЧЕН</span>
              <span className="text-gray-500">
                — для браузера поставь расширение прокси (SwitchyOmega) на 127.0.0.1:7897
              </span>
            </>
          )}
        </div>
        {channel?.hijack && (
          <div className="mt-3 border border-red-300 bg-red-50 rounded-lg p-3 flex items-center gap-3 flex-wrap">
            <span className="w-2.5 h-2.5 rounded-full bg-red-600 inline-block" />
            <span className="text-red-700 font-bold text-sm">
              ВЕСЬ СИСТЕМНЫЙ ТРАФИК ПЕРЕХВАТЧЕН (чужой fake-ip/TUN — виноват не канал)
            </span>
            <span className="text-red-600 text-sm flex-1 min-w-[240px]">
              {channel.hijack_detail || "следы 198.18.x в системе"} — программы и сайты напрямую работать не будут.
            </span>
            <button
              onClick={fixSystem}
              disabled={fixBusy}
              title="Погасить чужие перехватчики, снять их fake-ip маршруты (198.18.0.0/15), сбросить DNS-кэш"
              className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
            >
              {fixBusy ? <Loader2 size={14} className="animate-spin" /> : <RotateCcw size={14} />}
              Починить систему
            </button>
          </div>
        )}
      </div>

      {/* КАНАЛЫ ЮЗЕРА: единый список yaml-профилей и WG. Имя канала задаёт
          сам юзер (inline-ввод после выбора файла) — никаких автостемов. */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <FileUp size={18} className="text-sky-500" />
            <h3 className="font-bold text-gray-800">Твои каналы</h3>
            <span className="text-xs text-gray-400">
              профили подписок (.yaml) и WireGuard (.conf) — хранятся локально, никуда не отправляются
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={addChannelPick}
              disabled={listBusy || pendingAdd !== null}
              className="flex items-center gap-2 bg-sky-600 hover:bg-sky-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
            >
              {listBusy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              Добавить .yaml
            </button>
            <button
              onClick={importWgPick}
              disabled={listBusy || pendingWg !== null}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
            >
              <FileUp size={14} /> WG .conf
            </button>
          </div>
        </div>

        {/* Inline-ввод имени yaml-канала (после выбора файла). */}
        {pendingAdd && (
          <div className="mt-3 flex items-center gap-2 flex-wrap bg-sky-50 border border-sky-200 rounded-md p-3">
            <span className="text-sm text-gray-600">Название канала:</span>
            <input
              autoFocus
              value={pendingAdd.name}
              onChange={(e) => setPendingAdd({ ...pendingAdd, name: e.target.value })}
              onKeyDown={(e) => { if (e.key === "Enter") addChannelConfirm(); }}
              placeholder="например: NeVPN основной"
              className="flex-1 min-w-[200px] px-3 py-1.5 border border-sky-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-sky-300"
            />
            <button
              onClick={addChannelConfirm}
              disabled={listBusy}
              className="bg-sky-600 hover:bg-sky-700 disabled:bg-gray-300 text-white px-4 py-1.5 rounded-md text-sm font-bold"
            >
              Добавить
            </button>
            <button
              onClick={() => setPendingAdd(null)}
              disabled={listBusy}
              className="px-3 py-1.5 rounded-md border border-gray-300 text-gray-600 hover:bg-gray-50 text-sm"
            >
              Отмена
            </button>
          </div>
        )}

        {/* Inline-ввод имени WG-канала (после выбора .conf). */}
        {pendingWg && (
          <div className="mt-3 flex items-center gap-2 flex-wrap bg-emerald-50 border border-emerald-200 rounded-md p-3">
            <span className="text-sm text-gray-600">Название WG-канала:</span>
            <input
              autoFocus
              value={pendingWg.name}
              onChange={(e) => setPendingWg({ ...pendingWg, name: e.target.value })}
              onKeyDown={(e) => { if (e.key === "Enter") importWgConfirm(); }}
              placeholder="например: Proton NL"
              className="flex-1 min-w-[200px] px-3 py-1.5 border border-emerald-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-emerald-300"
            />
            <button
              onClick={importWgConfirm}
              disabled={listBusy}
              className="bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-300 text-white px-4 py-1.5 rounded-md text-sm font-bold"
            >
              Импортировать
            </button>
            <button
              onClick={() => setPendingWg(null)}
              disabled={listBusy}
              className="px-3 py-1.5 rounded-md border border-gray-300 text-gray-600 hover:bg-gray-50 text-sm"
            >
              Отмена
            </button>
          </div>
        )}

        {entries.length === 0 ? (
          <p className="mt-3 text-sm text-gray-500">
            Список пуст. Добавь файл подписки своего провайдера (mihomo/clash YAML)
            и назови канал как удобно — он появится в селекторе выше.
          </p>
        ) : (
          <ul className="mt-3 flex flex-col divide-y divide-gray-100">
            {entries.map((p) => {
              const isOn = mode === p.file;
              const isWg = p.type === "wg" || p.file === "__wg__";
              return (
                <li key={p.file} className="flex items-center gap-3 py-2 flex-wrap">
                  <span
                    className={
                      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold " +
                      (isWg ? "bg-emerald-100 text-emerald-700" : "bg-sky-100 text-sky-700")
                    }
                  >
                    {isWg ? "WG" : "YAML"}
                  </span>
                  <span className="font-semibold text-gray-800" title={p.file}>{p.name}</span>
                  {isOn && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold bg-green-100 text-green-700">
                      <CheckCircle2 size={12} /> ВКЛЮЧЁН
                    </span>
                  )}
                  {!isWg && (
                    <span className="text-xs text-gray-400">
                      добавлен {fmtAdded(p)} · {kb(p.size)}
                    </span>
                  )}
                  <span className="ml-auto">
                    <button
                      onClick={() => deleteEntry(p)}
                      disabled={listBusy}
                      title={isWg ? "Сбросить WG-креды и убрать канал из списка" : "Удалить канал и его файл с диска"}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-red-200 text-red-500 hover:bg-red-50 text-sm font-semibold disabled:opacity-50"
                    >
                      {isWg ? <RotateCcw size={14} /> : <Trash2 size={14} />}
                      {isWg ? "Сбросить" : "Удалить"}
                    </button>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* WG-КРЕДЫ: личные ключи WireGuard-провайдера юзера. Креды хранятся
          только в AppData на этой машине; шаблон публичный (без секретов) —
          креды подставляются при включении WG-канала. */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center gap-2">
          <KeyRound size={18} className="text-emerald-500" />
          <h3 className="font-bold text-gray-800">WireGuard-креды</h3>
        </div>
        <div className="mt-3 text-sm">
          {hasCreds ? (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />
              <span className="text-gray-700">
                заданы: <b>{creds.endpoint}</b> · адрес <b>{creds.address}</b>
                {creds.psk ? " · с PSK" : ""}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="w-2.5 h-2.5 rounded-full bg-gray-300 inline-block" />
              <span className="text-gray-500">
                не заданы — WG-канал не включится, пока не импортируешь .conf
              </span>
            </div>
          )}
          <p className="mt-2 text-xs text-gray-400">
            Где взять: у провайдера запасного VPN в личном кабинете (например, Proton VPN →
            Downloads → WireGuard configuration) скачай конфигурацию и импортируй файл .conf
            кнопкой «WG .conf» выше. Ключи хранятся только на этом компьютере.
          </p>
        </div>
      </div>
    </div>
  );
}
