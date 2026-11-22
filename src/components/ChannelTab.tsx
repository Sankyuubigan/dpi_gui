import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Globe, Plus, Trash2, FileUp, KeyRound, RotateCcw, Loader2, CheckCircle2, Cloud, Shield, Radio,
  FlaskConical, Skull, Youtube,
} from "lucide-react";

// ==== «Тест каналов»: стейт на уровне МОДУЛЯ (21.11.26) ====
// Вкладку размонтирует при смене — useState умирал и стирал все результаты.
// Кеш живёт вне компонента: события бэкенда пишутся в него, даже когда юзер
// на другой вкладке; компонент при монтировании подписывается на перерисовку.
const testCache: { results: Record<string, any>; running: boolean } = {
  results: {},
  running: false,
};
const testCacheSubs = new Set<() => void>();
const testCacheSet = (patch: Partial<typeof testCache>) => {
  Object.assign(testCache, patch);
  testCacheSubs.forEach((f) => f());
};
// Слушатель один на модуль и живёт до конца приложения: не рвётся на unmount,
// поэтому прогресс не теряется при переключении вкладок посреди теста.
let testListenerBound = false;
const bindTestListener = async () => {
  if (testListenerBound) return;
  testListenerBound = true;
  await listen("channel-test-progress", (ev: any) => {
    const { id, state, result } = ev.payload;
    testCacheSet({
      results: {
        ...testCache.results,
        [id]: state === "running" ? { running: true } : { ...testCache.results[id], ...result },
      },
    });
  });
};

// Иконки статуса канала из ПОСЛЕДНЕГО теста (просьба юзера 22.11.26):
// мёртв — череп, жив — иконки того, что реально прошло (ютуб / иностранные
// сайты-гео); теста не было или канал не тестировался (not_running) — иконок
// нет. Стейт результатов — модульный testCache: иконки честно показывают
// «на момент последнего теста», после рестарта приложения честно пусто.
function TestStatusIcons({ r }: { r: any }) {
  if (!r || r.running) return null;
  if (r.status === "dead" || r.status === "error") {
    return (
      <span
        title="последний тест: канал МЁРТВ — ни одна проба не прошла"
        className="inline-flex items-center"
      >
        <Skull size={15} className="text-red-600" />
      </span>
    );
  }
  if ((r.status === "ok" || r.status === "partial") && (r.youtube?.ok || r.geo?.ok)) {
    return (
      <span className="inline-flex items-center gap-0.5">
        {r.youtube?.ok && (
          <span title="последний тест: ютуб работает" className="inline-flex items-center">
            <Youtube size={15} className="text-red-500" />
          </span>
        )}
        {r.geo?.ok && (
          <span title="последний тест: иностранные сайты открываются (гео-обход)" className="inline-flex items-center">
            <Globe size={15} className="text-emerald-600" />
          </span>
        )}
      </span>
    );
  }
  // not_running / нет пройденных проб ютуб-гео — без иконки
  return null;
}

/// Вкладка «Канал» (PRP 18.11.26, редизайн по требованию юзера): селектор
/// каналов строится ИЗ РЕЕСТРА юзера (никаких хардкод-режимов; 21.11.26 —
/// имя канала = метод, задаёт бэкенд, переименование руками убрано). Личное
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
  // pendingAdd/pendingWg убраны (21.11.26): имя канала = метод, задаёт бэкенд;
  // флоу добавления одношаговый (файл-диалог → invoke).
  // WG-креды (статус без приватного ключа).
  const [creds, setCreds] = useState<any>({ present: false });
  // WARP-учётка (Этап B): статус без приватных полей (ключи/token не отдаются).
  const [warp, setWarp] = useState<any>({ present: false });
  const [warpBusy, setWarpBusy] = useState(false);
  // AWG/Proton-over-AWG (PRP 20.11.26): статус без приватных полей.
  const [awg, setAwg] = useState<any>({ has_account: false, pawg_available: false });
  const [awgBusy, setAwgBusy] = useState(false);
  // Psiphon-сайдкар (aether.exe): статус для честной карточки.
  const [psiphon, setPsiphon] = useState<any>({ installed: false, running: false, ready: false });

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
    invoke("warp_status")
      .then(setWarp)
      .catch((e: any) => logMsg(`Канал: статус WARP недоступен: ${e}`));
    invoke("awg_status")
      .then(setAwg)
      .catch((e: any) => logMsg(`Канал: статус AWG недоступен: ${e}`));
    invoke("psiphon_status")
      .then(setPsiphon)
      .catch((e: any) => logMsg(`Канал: статус Psiphon недоступен: ${e}`));
  };
  useEffect(refreshRegistry, []);

  // ==== Плашка «Тест каналов» (21.11.26): каждый канал тестируется ЖИВЬЁМ
  // (ютуб/ТСПУ, гео, страна выхода, скорость). Прогресс — события бэкенда,
  // итог — invoke channel_test_all. Тест = «сейчас», не гарантия 24/7 (§9). ====
  // Результаты — из module-кеша (переживают смену вкладок); подписка гонит
  // перерисовку при каждом обновлении кеша.
  const [, setTestTick] = useState(0);
  useEffect(() => {
    const cb = () => setTestTick((x: number) => x + 1);
    testCacheSubs.add(cb);
    void bindTestListener();
    return () => {
      testCacheSubs.delete(cb);
    };
  }, []);
  const testResults = testCache.results;
  const testRunning = testCache.running;

  const runChannelTest = async () => {
    if (testRunning) return;
    testCacheSet({ running: true });
    testCacheSet({ results: {} });
    logMsg("Канал: тестирую все каналы живьём (ютуб/гео/страна/скорость, ~2–3 мин)...");
    try {
      const results: any[] = await invoke("channel_test_all");
      const map: Record<string, any> = {};
      for (const r of results) map[r.id] = r;
      testCacheSet({ results: map });
      const okCount = results.filter((r) => r.status === "ok").length;
      const notRunCount = results.filter((r) => r.status === "not_running").length;
      const testedCount = results.length - notRunCount;
      logMsg(
        `Канал: тест завершён — РАБОТАЕТ: ${okCount} из ${testedCount}` +
          (notRunCount ? ` (не запущено: ${notRunCount})` : "") +
          ".",
      );
    } catch (e: any) {
      logMsg(`Канал: ошибка теста: ${e}`);
    } finally {
      testCacheSet({ running: false });
    }
  };

  const retestOne = async (id: string) => {
    if (testRunning) return;
    testCacheSet({ results: { ...testCache.results, [id]: { running: true } } });
    logMsg("Канал: перетест одного канала...");
    try {
      const r: any = await invoke("channel_test_one", { id });
      testCacheSet({ results: { ...testCache.results, [id]: r } });
    } catch (e: any) {
      testCacheSet({ results: { ...testCache.results, [id]: { status: "dead", error: String(e) } } });
    }
  };
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

  // ==== Добавление yaml-канала: файл-диалог → регистрация (имя = метод,
  // задаёт бэкенд — 21.11.26: переименование руками убрано) ====
  const addChannelPick = async () => {
    if (listBusy) return;
    const path = await open({
      multiple: false,
      filters: [{ name: "Профиль mihomo/clash (YAML)", extensions: ["yaml", "yml"] }],
    });
    if (!path) return;
    setListBusy(true);
    logMsg("Канал: добавляю профиль (имя — канон метода)...");
    try {
      const reg: any = await invoke("paid_profile_add", { path: String(path) });
      setRegistry(reg);
      logMsg("Канал: добавлен.");
    } catch (e: any) {
      logMsg(`Канал: не добавить канал: ${e}`);
    } finally {
      setListBusy(false);
    }
  };

  // ==== Импорт WG .conf: файл-диалог → креды + запись в реестре ====
  const importWgPick = async () => {
    if (listBusy) return;
    const path = await open({
      multiple: false,
      filters: [{ name: "WireGuard конфигурация", extensions: ["conf"] }],
    });
    if (!path) return;
    setListBusy(true);
    logMsg("Канал: импортирую WireGuard .conf...");
    try {
      const s: any = await invoke("wg_creds_import", { path: String(path) });
      setCreds(s);
      refreshRegistry(); // wg_channel_sync изменил реестр — перечитать
      logMsg(`Канал: креды импортированы (${s.endpoint}).`);
    } catch (e: any) {
      logMsg(`Канал: не импортировать .conf: ${e}`);
    } finally {
      setListBusy(false);
    }
  };

  // ==== WARP (v2 MASQUE): регистрация в 1 клик / сброс (wgcf-импорт убран) ====
  const warpRegister = async () => {
    if (warpBusy) return;
    setWarpBusy(true);
    logMsg("WARP: регистрирую анонимную учётку Cloudflare...");
    try {
      const s: any = await invoke("warp_setup", { action: "register" });
      setWarp(s);
      refreshRegistry(); // warp_channel_sync добавил канал в реестр
      logMsg(`WARP: учётка готова (${s.endpoint}). Канал «WARP (Cloudflare)» — в селекторе выше.`);
    } catch (e: any) {
      logMsg(`WARP: не зарегистрировать: ${e}`);
    } finally {
      setWarpBusy(false);
    }
  };

  const warpReset = async () => {
    if (warpBusy) return;
    if (mode === "__warp__") {
      logMsg("WARP: сначала выключи WARP-канал — сброс учётки при активном туннеле запрещён.");
      return;
    }
    if (!confirm("Сбросить WARP-учётку? Туннель перестанет работать, пока не зарегистрируешься заново.")) return;
    setWarpBusy(true);
    try {
      const s: any = await invoke("warp_setup", { action: "reset" });
      setWarp(s);
      refreshRegistry();
      logMsg("WARP: учётка сброшена.");
    } catch (e: any) {
      logMsg(`WARP: не сбросить учётку: ${e}`);
    } finally {
      setWarpBusy(false);
    }
  };

  // ==== AWG (PRP 20.11.26): регистрация (warpscout) / рескан / сброс ====
  const awgAction = async (action: "register" | "rescan" | "reset") => {
    if (awgBusy) return;
    if (action === "reset") {
      if (mode === "__awg__" || mode === "__pawg__") {
        logMsg("AWG: сначала выключи канал — сброс учётки при активном туннеле запрещён.");
        return;
      }
      if (!confirm("Сбросить AWG-учётку? Каналы «WARP AWG (YouTube)» и «AWG Proton WARP» перестанут работать до новой регистрации.")) return;
    }
    setAwgBusy(true);
    logMsg(
      action === "register"
        ? "AWG: регистрирую учётку (warpscout: прямая → релея → резервный путь через Psiphon)..."
        : action === "rescan"
          ? "AWG: пересканирую живые эндпоинты (до 5 мин)..."
          : "AWG: сбрасываю учётку..."
    );
    try {
      const s: any = await invoke("awg_setup", { action });
      setAwg(s);
      refreshRegistry();
      if (action === "register") logMsg("AWG: учётка готова. Каналы «WARP AWG (YouTube)» и «AWG Proton WARP (гео)» — в селекторе.");
      if (action === "rescan") logMsg(`AWG: эндпоинтов: ${s.endpoints_count} (источник: ${s.endpoints_source === "scan" ? "свежий скан" : "встроенный шортлист"}).`);
      if (action === "reset") logMsg("AWG: учётка сброшена.");
    } catch (e: any) {
      logMsg(`AWG: ошибка: ${e}`);
    } finally {
      setAwgBusy(false);
    }
  };

  // Удаление из списка: yaml — файл+запись; WG-запись удаляется только
  // вместе с кредами («Сбросить») — иначе импорт вернул бы её молча.
  const deleteEntry = async (p: any) => {
    if (listBusy) return;
    if (p.type === "warp" || p.file === "__warp__") {
      // WARP: «Сбросить» = удалить учётку (confirm и честные гейты внутри).
      warpReset();
      return;
    }
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
    if (p.type === "awg" || p.type === "pawg" || p.file === "__awg__" || p.file === "__pawg__") {
      // AWG/pawg — общая учётка: «Сбросить» = awg_reset (уберёт обе записи
      // из реестра; pawg без AWG-туннеля невозможен по построению).
      awgAction("reset");
      return;
    }
    if (p.type === "psiphon" || p.file === "__psiphon__") {
      // Psiphon — постоянный канал реестра (не данные юзера): удалять нечего.
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
  const hasWarpAccount = Boolean(warp?.present);
  const hasAwgAccount = Boolean(awg?.has_account);
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
              const isWarp = p.type === "warp" || p.file === "__warp__";
              const isAwg = p.type === "awg" || p.file === "__awg__";
              const isPawg = p.type === "pawg" || p.file === "__pawg__";
              const isPsiphon = p.type === "psiphon" || p.file === "__psiphon__";
              const locked =
                (p.type === "wg" && !hasCreds) ||
                (isWarp && !hasWarpAccount) ||
                (isAwg && !hasAwgAccount) ||
                (isPawg && !awg?.pawg_available) ||
                (isPsiphon && (!hasWarpAccount || !psiphon?.installed));
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
                        : isWarp
                          ? hasWarpAccount
                            ? "WARP-канал Cloudflare (MASQUE, TCP:443): geo-домены через туннель, остальное напрямую (банки видят RU-IP). СТАБИЛЬНОСТЬ НЕ ПОДТВЕРЖДЕНА (§9) — резерв, флапает по времени суток"
                            : "Нет WARP-учётки — нажми «Зарегистрировать» в карточке ниже"
                          : isAwg
                            ? hasAwgAccount
                              ? "WARP-ключи + amnezia-junk (AWG): ютуб и geo-домены через туннель, остальное напрямую. СТАБИЛЬНОСТЬ НЕ ПОДТВЕРЖДЕНА (§9)"
                              : "Нет AWG-учётки — нажми «Зарегистрировать» в карточке ниже"
                            : isPawg
                              ? awg?.pawg_available
                                ? "Proton WG поверх AWG-туннеля (UDP-в-UDP): выход NL, гео-доступ. СТАБИЛЬНОСТЬ НЕ ПОДТВЕРЖДЕНА (§9)"
                                : "Нужны AWG-учётка и WG-креды Proton (см. карточки ниже)"
                              : isPsiphon
                                ? hasWarpAccount && psiphon?.installed
                                  ? "Psiphon (сеть Psiphon через aether): медленный резерв ~0.2 МБ/с. СТАБИЛЬНОСТЬ НЕ ПОДТВЕРЖДЕНА (§9)"
                                  : "Нужны WARP-учётка и aether.exe в бандле"
                                : `Переключить канал на «${p.name}» (yaml-профиль)`
                  }
                  className={
                    "inline-flex items-center gap-1.5 px-4 py-2 rounded-md font-bold text-sm transition-colors border " +
                    ((channelBusy || locked)
                      ? "border-gray-200 text-gray-400 cursor-not-allowed"
                      : active
                        ? p.type === "wg"
                          ? "border-emerald-500 bg-emerald-500 text-white"
                          : isWarp
                            ? "border-indigo-500 bg-indigo-500 text-white"
                            : isAwg || isPawg
                              ? "border-violet-500 bg-violet-500 text-white"
                              : isPsiphon
                                ? "border-amber-500 bg-amber-500 text-white"
                                : "border-sky-500 bg-sky-500 text-white"
                        : "border-gray-300 text-gray-600 hover:bg-gray-50")
                  }
                >
                  <TestStatusIcons r={testResults[p.file]} />
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
              {mode === "__warp__" && (
                <span className="text-gray-600">
                  {channel.warp?.ok && channel.warp?.warp === "on" ? (
                    channel.warp?.loc === "RU" ? (
                      <span className="text-amber-600 font-semibold">
                        — туннель жив, но выход RU: варп на этом провайдере гео не сменит
                      </span>
                    ) : (
                      <span className="text-green-700 font-semibold">
                        — туннель жив (Cloudflare, выход {channel.warp?.loc || "?"})
                      </span>
                    )
                  ) : channel.warp?.checked_ts ? (
                    <span className="text-amber-600 font-semibold" title={channel.warp?.error || ""}>
                      — туннель под вопросом: {channel.warp?.error || "проба не отвечала"}
                    </span>
                  ) : (
                    <span className="text-gray-500"> — ждём первую trace-пробу…</span>
                  )}
                </span>
              )}
              {(mode === "__awg__" || mode === "__pawg__" || mode === "__psiphon__") && (
                <span className="text-gray-600">
                  {channel.warp?.ok ? (
                    mode === "__awg__" ? (
                      channel.warp?.warp === "on" ? (
                        <span className="text-green-700 font-semibold">
                          — туннель жив (AWG поверх WARP, выход {channel.warp?.loc || "?"})
                        </span>
                      ) : (
                        <span className="text-amber-600 font-semibold" title={channel.warp?.error || ""}>
                          — туннель под вопросом: {channel.warp?.error || "проба не отвечала"}
                        </span>
                      )
                    ) : channel.warp?.loc && channel.warp?.loc !== "RU" ? (
                      <span className="text-green-700 font-semibold">
                        — туннель жив (выход {channel.warp?.loc})
                        {mode === "__psiphon__" && " · медленный резерв"}
                      </span>
                    ) : (
                      <span className="text-amber-600 font-semibold" title={channel.warp?.error || ""}>
                        — туннель под вопросом: {channel.warp?.error || "проба не отвечала"}
                      </span>
                    )
                  ) : channel.warp?.checked_ts ? (
                    <span className="text-amber-600 font-semibold" title={channel.warp?.error || ""}>
                      — туннель под вопросом: {channel.warp?.error || "проба не отвечала"}
                    </span>
                  ) : (
                    <span className="text-gray-500"> — ждём первую trace-пробу…</span>
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
        {/* PAC-подхват браузеров (Этап A 19.11.26): честный чип — система
            либо слушает наш proxy.pac, либо нет. Тумблер — «Настройки →
            Маршрутизатор». */}
        {channel && (
          <div className="mt-1 text-sm flex items-center gap-2 flex-wrap">
            {channel.pac_on ? (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block" />
                <span className="text-sky-700 font-semibold">БРАУЗЕРЫ ПОДХВАЧЕНЫ (PAC)</span>
                <span className="text-gray-500">— домены групп «канал» идут через прокси автоматически</span>
              </>
            ) : (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-gray-400 inline-block" />
                <span className="text-gray-600">Подхват браузеров выключен</span>
                <span className="text-gray-500">— тумблер PAC в «Настройках → Маршрутизатор»</span>
              </>
            )}
          </div>
        )}
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
              disabled={listBusy}
              className="flex items-center gap-2 bg-sky-600 hover:bg-sky-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
            >
              {listBusy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              Добавить .yaml
            </button>
            <button
              onClick={importWgPick}
              disabled={listBusy}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
            >
              <FileUp size={14} /> WG .conf
            </button>
          </div>
        </div>

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
              const isWarp = p.type === "warp" || p.file === "__warp__";
              const isAwg = p.type === "awg" || p.file === "__awg__";
              const isPawg = p.type === "pawg" || p.file === "__pawg__";
              const isPsiphon = p.type === "psiphon" || p.file === "__psiphon__";
              return (
                <li key={p.file} className="flex items-center gap-3 py-2 flex-wrap">
                  <span
                    className={
                      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold " +
                      (isWarp
                        ? "bg-indigo-100 text-indigo-700"
                        : isWg
                          ? "bg-emerald-100 text-emerald-700"
                          : isAwg || isPawg
                            ? "bg-violet-100 text-violet-700"
                            : isPsiphon
                              ? "bg-amber-100 text-amber-700"
                              : "bg-sky-100 text-sky-700")
                    }
                  >
                    {isWarp ? "WARP" : isWg ? "WG" : isAwg ? "AWG" : isPawg ? "PAWG" : isPsiphon ? "PSIPHON" : "YAML"}
                  </span>
                  <span className="font-semibold text-gray-800" title={p.file}>{p.name}</span>
                  {isOn && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold bg-green-100 text-green-700">
                      <CheckCircle2 size={12} /> ВКЛЮЧЁН
                    </span>
                  )}
                  {(isWarp || isAwg || isPawg || isPsiphon) && (
                    <span className="text-xs text-amber-600" title="Канал ещё не прошёл суточную проверку стабильности (правило §9) — не включай его в ночь, когда нужен доступ">
                      ⚠ стабильность не подтверждена
                    </span>
                  )}
                  {isAwg && (
                    <span className="text-xs text-gray-400">
                      учётка AWG · {awg?.endpoints_count ?? 0} эндпоинтов · {awg?.endpoints_source === "scan" ? "свежий скан" : "шортлист"}
                    </span>
                  )}
                  {isPawg && (
                    <span className="text-xs text-gray-400">
                      Proton WG поверх AWG-туннеля — выход NL
                    </span>
                  )}
                  {isPsiphon && (
                    <span className="text-xs text-gray-400">
                      сеть Psiphon (aether) — медленный резерв: {psiphon?.ready ? "готов" : psiphon?.running ? "греется" : "выключен"}
                    </span>
                  )}
                  {!isWg && !isWarp && !isAwg && !isPawg && !isPsiphon && (
                    <span className="text-xs text-gray-400">
                      добавлен {fmtAdded(p)} · {kb(p.size)}
                    </span>
                  )}
                  {isWarp && (
                    <span className="text-xs text-gray-400">
                      {warp?.legacy_account
                        ? "старая wgcf-учётка (v1) — «Сбросить» и зарегистрировать заново (MASQUE)"
                        : "учётка Cloudflare MASQUE (TCP:443)"}
                    </span>
                  )}
                  <span className="ml-auto">
                    {!isPsiphon && (
                      <button
                        onClick={() => deleteEntry(p)}
                        disabled={listBusy}
                        title={
                          isWarp
                            ? "Сбросить WARP-учётку и убрать канал из списка"
                            : isWg
                              ? "Сбросить WG-креды и убрать канал из списка"
                              : isAwg || isPawg
                                ? "Сбросить AWG-учётку и убрать оба канала (AWG и Proton) из списка"
                                : "Удалить канал и его файл с диска"
                        }
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-red-200 text-red-500 hover:bg-red-50 text-sm font-semibold disabled:opacity-50"
                      >
                        {isWg || isWarp || isAwg || isPawg ? <RotateCcw size={14} /> : <Trash2 size={14} />}
                        {isWg || isWarp || isAwg || isPawg ? "Сбросить" : "Удалить"}
                      </button>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Тест каналов (21.11.26): кнопка → каждый канал тестируется ЖИВЬЁМ
          (ютуб/ТСПУ, гео-обход, страна выхода, скорость). Активный канал — на
          своём боевом порту, остальные — тестовый стенд; гашение по PID,
          активный не трогается. Тест = «сейчас», не гарантия 24/7 (§9). */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <FlaskConical size={18} className="text-purple-500" />
            <h3 className="font-bold text-gray-800">Тест каналов</h3>
            <span className="px-2 py-0.5 rounded text-xs font-bold bg-gray-100 text-gray-500">
              проверка «сейчас», не 24/7
            </span>
          </div>
          <button
            onClick={runChannelTest}
            disabled={testRunning}
            title="Каждый канал поднимается живьём и проверяется реальными HTTP-пробами"
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
          >
            {testRunning ? <Loader2 size={14} className="animate-spin" /> : <FlaskConical size={14} />}
            Протестировать все каналы
          </button>
        </div>
        {Object.keys(testResults).length > 0 && !testRunning && (() => {
          // Сводка прогона — дублирует строку лога «тест завершён — РАБОТАЕТ: N из M»,
          // но видна прямо на плашке (юзер не должен лезть в dpi_gui.log).
          const vals = Object.values(testResults) as any[];
          const ok = vals.filter((r: any) => r.status === "ok").length;
          const partial = vals.filter((r: any) => r.status === "partial").length;
          const dead = vals.filter((r: any) => r.status === "dead" || r.status === "error").length;
          const notRun = vals.filter((r: any) => r.status === "not_running").length;
          const tested = vals.length - notRun;
          return (
            <p
              className={
                "mt-3 text-sm font-bold " +
                (tested === 0
                  ? "text-gray-500"
                  : ok === tested
                    ? "text-green-700"
                    : ok > 0
                      ? "text-amber-700"
                      : "text-red-600")
              }
            >
              Итог: РАБОТАЕТ {ok} из {tested}
              {partial > 0 ? ` · ⚠ ЧАСТИЧНО ${partial}` : ""}
              {dead > 0 ? ` · ❌ МЁРТВ ${dead}` : ""}
              {notRun > 0 ? ` · ⚪ НЕ ЗАПУЩЕН ${notRun}` : ""}
              {tested === 0 ? " — ни один канал не был запущен, тестировать нечего" : ""}
              {ok === 0 && tested > 0 ? " — ни один запущенный канал не прошёл пробы" : ""}
            </p>
          );
        })()}
        {Object.keys(testResults).length > 0 && (
          <ul className="mt-3 divide-y divide-gray-100">
            {(registry.profiles ?? []).map((p: any) => {
              const r = testResults[p.file];
              if (!r) return null;
              const [mark, cls] =
                r.status === "ok"
                  ? ["✅ РАБОТАЕТ", "bg-green-100 text-green-700"]
                  : r.status === "partial"
                    ? ["⚠ ЧАСТИЧНО", "bg-yellow-100 text-yellow-700"]
                    : r.status === "not_running"
                      ? ["⚪ НЕ ЗАПУЩЕН", "bg-gray-100 text-gray-600"]
                      : ["❌ МЁРТВ", "bg-red-100 text-red-700"];
              return (
                <li key={p.file} className="py-2 text-sm flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded font-bold text-xs ${cls}`}>{mark}</span>
                  <span className="font-semibold text-gray-700">{p.name}</span>
                  {r.running && <Loader2 size={14} className="animate-spin text-gray-400" />}
                  {r.country && <span className="text-gray-500">выход {r.country}</span>}
                  {r.youtube && (
                    <span className={r.youtube.ok ? "text-green-600" : "text-red-500"}>
                      ютуб: {r.youtube.detail}
                    </span>
                  )}
                  {r.geo && (
                    <span className={r.geo.ok ? "text-green-600" : "text-red-500"}>
                      гео: {r.geo.detail}
                    </span>
                  )}
                  {r.speed && <span className="text-gray-500">скорость: {r.speed.detail}</span>}
                  {r.note && <span className="text-gray-400">{r.note}</span>}
                  {r.error && <span className="text-red-500">{r.error}</span>}
                  <span className="ml-auto">
                    <button
                      onClick={() => retestOne(p.file)}
                      disabled={testRunning}
                      title="Перетестировать только этот канал"
                      className="px-2 py-1 rounded border border-gray-300 text-gray-500 hover:bg-gray-50 text-xs disabled:opacity-50"
                    >
                      ↻ снова
                    </button>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
        {testRunning && (
          <p className="mt-2 text-xs text-gray-400">
            Тест идёт: канал поднимается живьём, пробы реальные (Psiphon греется до 40с)...
          </p>
        )}
      </div>

      {/* WARP-УЧЁТКА (Этап B): четвёртый канал — бесплатный туннель Cloudflare.
          Селективный по построению: домены группы «geo» → WARP, остальное DIRECT
          (банки/госуслуги видят RU-IP — инвариант «не режим всего трафика»).
          Регистрация анонимная в 1 клик; ключи/token живут только в AppData. */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Cloud size={18} className="text-indigo-500" />
            <h3 className="font-bold text-gray-800">WARP (Cloudflare, бесплатно, резерв)</h3>
            <span
              className="text-xs text-amber-600"
              title="Канал ещё не прошёл суточную проверку стабильности (правило §9); живые пробы показывают флап по времени суток (вечерний пик — мёртв). Резерв: не считай его решением"
            >
              ⚠ стабильность не подтверждена
            </span>
          </div>
          <div className="flex items-center gap-2">
            {hasWarpAccount ? (
              <button
                onClick={warpReset}
                disabled={warpBusy || mode === "__warp__"}
                title={mode === "__warp__" ? "Сначала выключи WARP-канал" : "Удалить учётку и убрать канал из списка"}
                className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
              >
                {warpBusy ? <Loader2 size={14} className="animate-spin" /> : <RotateCcw size={14} />}
                Сбросить учётку
              </button>
            ) : (
              <button
                onClick={warpRegister}
                disabled={warpBusy}
                title="Программа сама создаст анонимную учётку WARP MASQUE и запишет ключи локально"
                className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
              >
                {warpBusy ? <Loader2 size={14} className="animate-spin" /> : <Cloud size={14} />}
                Зарегистрировать
              </button>
            )}
          </div>
        </div>
        <div className="mt-3 text-sm">
          {hasWarpAccount ? (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />
              <span className="text-gray-700">
                учётка готова: <b>{warp.endpoint}</b> · адрес <b>{warp.address}</b> · туннель MASQUE (TCP:443)
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="w-2.5 h-2.5 rounded-full bg-gray-300 inline-block" />
              <span className="text-gray-500">
                учётки нет — канал «WARP» заблокирован в селекторе, пока не зарегистрируешься
              </span>
            </div>
          )}
          <p className="mt-2 text-xs text-gray-400">
            Что это: бесплатный VPN-туннель Cloudflare (MASQUE поверх TCP:443 — UDP не нужен,
            работает там, где WireGuard порезан провайдером) как четвёртый канал. Селективно:
            домены группы «geo» (aistudio, Adobe и т.п. — вкладка «Настройки → Маршрутизатор»)
            идут через WARP, всё остальное — напрямую, банки и госуслуги видят твой обычный IP.
            Выходная страна — как повезёт (edge Cloudflare): честно показывается в статусе
            канала; loc=RU → жёлтая плашка «гео не сменит».
          </p>
          <p className="mt-1 text-xs text-gray-400">
            Регистрация: если ни канал, ни обход сейчас не включены, программа на время запроса
            поднимет временный однодоменный обход (дизсинк из твоего активного профиля) и погасит
            его сама. wgcf-импорт убран: старые ключи Curve25519 с MASQUE-каналом несовместимы —
            учётка создаётся только кнопкой «Зарегистрировать».
          </p>
        </div>
      </div>

      {/* AWG-КАНАЛ (PRP 20.11.26): пятый/шестой каналы — WARP по AmneziaWG (AWG)
          и Proton WireGuard поверх AWG-туннеля. Учётка AWG регистрируется warpscout
          (анонимно, ключи только в AppData); junk-параметры (i1 и т.п.) ломают
          DPI-распознавание WireGuard — селективно: группа «geo» → AWG-туннель. */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-violet-500" />
            <h3 className="font-bold text-gray-800">WARP AWG / AWG Proton WARP (бесплатно, резерв)</h3>
            <span
              className="px-2 py-0.5 rounded text-xs font-bold bg-amber-100 text-amber-700"
              title="Каналы ещё не прошли суточную проверку стабильности (правило §9)"
            >
              ⚠ стабильность не подтверждена
            </span>
          </div>
          <div className="flex items-center gap-2">
            {/* «Зарегистрировать» скрыта при готовой учётке (паттерн WARP-карточки):
                повторная регистрация перезаписала бы ключи/шортлист. Легальный путь
                перерегистрации — «Сбросить учётку» → кнопка возвращается. */}
            {!hasAwgAccount && (
              <button
                onClick={() => awgAction("register")}
                disabled={awgBusy}
                title="Программа сама создаст анонимную AWG-учётку (warpscout) и запишет ключи локально; при блокировке регистрации поднимет временный обход"
                className="flex items-center gap-2 bg-violet-600 hover:bg-violet-700 disabled:bg-gray-300 text-white px-4 py-2 rounded-md font-bold text-sm transition-colors"
              >
                {awgBusy ? <Loader2 size={14} className="animate-spin" /> : <Shield size={14} />}
                Зарегистрировать
              </button>
            )}
            {hasAwgAccount && (
              <>
                <button
                  onClick={() => awgAction("rescan")}
                  disabled={awgBusy}
                  title="Пересканировать живые AWG-эндпоинты (до 5 минут) и обновить список в конфигах"
                  className="flex items-center gap-2 border border-violet-200 text-violet-600 hover:bg-violet-50 px-3 py-2 rounded-md font-semibold text-sm"
                >
                  {awgBusy ? <Loader2 size={14} className="animate-spin" /> : <Radio size={14} />}
                  Пересканировать
                </button>
                <button
                  onClick={() => awgAction("reset")}
                  disabled={awgBusy}
                  title="Сбросить AWG-учётку и убрать оба канала (AWG и Proton) из списка"
                  className="flex items-center gap-2 border border-red-200 text-red-500 hover:bg-red-50 px-3 py-2 rounded-md font-semibold text-sm"
                >
                  <RotateCcw size={14} />
                  Сбросить учётку
                </button>
              </>
            )}
          </div>
        </div>
        <div className="mt-3 text-sm">
          {hasAwgAccount ? (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />
              <span className="text-gray-700">
                учётка готова: <b>{awg?.endpoints_count ?? 0}</b> эндпоинтов ({awg?.endpoints_source === "scan" ? "свежий скан" : "встроенный шортлист"}) · канал «AWG Proton WARP» {awg?.pawg_available ? "доступен (импортируй WG-креды Proton)" : "нужен импорт WG-кредов Proton (карточка ниже)"}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="w-2.5 h-2.5 rounded-full bg-gray-300 inline-block" />
              <span className="text-gray-500">
                учётки нет — каналы «WARP AWG» и «AWG Proton WARP» заблокированы в селекторе, пока не зарегистрируешься
              </span>
            </div>
          )}
          <p className="mt-2 text-xs text-gray-400">
            Что это: туннель Cloudflare WARP по протоколу AmneziaWG (обфусцированный WireGuard
            с junk-пакетами — проходит там, где обычный WireGuard распознаётся DPI и режется).
            Шестой канал «AWG Proton WARP» — это WireGuard-профиль Proton (креды
            юзера), завёрнутый в AWG-туннель (dialer-proxy): выход — обычный NL-IP
            Proton (гео-обход), транспорт — бесплатный WARP. Селективно, как WARP:
            только группа «geo».
          </p>
          <p className="mt-1 text-xs text-gray-400">
            Регистрация: warpscout пробует прямую → через релею → через временный Psiphon-bootstrap;
            ключи и токен живут только в AppData. Эндпоинты пересканируй, если канал перестал
            подниматься. Стабильность обоих каналов ещё не проверена суточным прогоном (§9).
          </p>
        </div>
      </div>

      {/* PSIPHON-КАНАЛ (PRP 20.11.26): седьмой канал — сеть Psiphon через aether.
          Медленный (~0.2 МБ/с), но живучий: обфусцированные туннели под видом HTTPS.
          Резерв по §9, честная метка. Ходит через WARP masque (listeners[].proxy). */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Radio size={18} className="text-amber-500" />
            <h3 className="font-bold text-gray-800">Psiphon (бесплатно, резерв)</h3>
            <span
              className="px-2 py-0.5 rounded text-xs font-bold bg-amber-100 text-amber-700"
              title="Канал ещё не прошёл суточную проверку стабильности (правило §9)"
            >
              ⚠ стабильность не подтверждена
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={
                "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold " +
                (psiphon?.ready
                  ? "bg-green-100 text-green-700"
                  : psiphon?.running
                    ? "bg-yellow-100 text-yellow-700"
                    : "bg-gray-100 text-gray-500")
              }
            >
              {psiphon?.ready ? "ГОТОВ" : psiphon?.running ? "ГРЕЕТСЯ" : psiphon?.installed ? "УСТАНОВЛЕН" : "ВЫКЛЮЧЕН"}
            </span>
          </div>
        </div>
        <div className="mt-3 text-sm">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={"w-2.5 h-2.5 rounded-full inline-block " + (psiphon?.ready ? "bg-green-500" : psiphon?.running ? "bg-yellow-400" : "bg-gray-300")} />
            <span className="text-gray-700">
              {psiphon?.ready
                ? "сайдкар aether работает — канал «Psiphon» готов к включению"
                : psiphon?.running
                  ? "сайдкар запускается (транспорт Psiphon греется ~15 с)"
                  : "сайдкар выключен — поднимется автоматически при включении канала «Psiphon»"}
            </span>
          </div>
          <p className="mt-2 text-xs text-gray-400">
            Что это: сеть Psiphon (обфусцированные туннели под видом HTTPS-трафика) как седьмой
            канал — медленный (~0.2 МБ/с), но живучий. Скорость не главное (§9): канал нужен как
            аварийный резерв, когда и платный, и бесплатные туннели лежат. Выход — DE (регион
            Psiphon), селективно: только группа «geo». Работает ПОВЕРХ WARP masque (upstream):
            masque лёг — Psiphon лёг вместе с ним (22.11: EOF-пробы ровно в окно мёртвого
            masque), то есть независимым резервом он не является.
          </p>
        </div>
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
