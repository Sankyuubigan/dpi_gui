import type { Dispatch, SetStateAction } from "react";

/// Имена долгих операций для кнопок «Стоп» (invoke "cancel_operation").
/// SSOT-пара: константы в src-tauri/src/cancel.rs — строки должны совпадать
/// байт-в-байт, бэкенд различает операции ровно по ним.
export const OP_SITE_ANALYSIS = "site_analysis";
export const OP_DNS_PICK = "dns_pick";
export const OP_PROFILE_TEST = "profile_test";
export const OP_DIAGNOSTICS = "diagnostics";

/// Обёртка запуска долгой операции: activeOp (имя операции) живёт ровно пока
/// она идёт; кнопка «Стоп» рендерится при activeOp === имя && isTesting.
/// isTesting по-прежнему рулят сами вкладки — у них есть и быстрые операции
/// без «Стопа» (hosts, «Починить сайт»), которые activeOp не трогают.
export async function runOp(
  setActiveOp: Dispatch<SetStateAction<string | null>>,
  name: string,
  fn: () => Promise<void>,
): Promise<void> {
  setActiveOp(name);
  try {
    await fn();
  } finally {
    setActiveOp(null);
  }
}
