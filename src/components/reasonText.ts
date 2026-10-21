// ОДНО место сборки человекочитаемых причин подозрений (PRP §7.4).
// Машинные значения `reason` приходят из бэкенда: "rst" | "retrans".
// Формулировки синхронизированы с текстом лога в domain_monitor.rs (WorkerCtx::emit).
export function reasonToHuman(reason: string): string {
  switch (reason) {
    case "rst":
      return "сервер отклонил подключение (RST)";
    case "retrans":
      return "сервер молчит, пакеты не доходят";
    default:
      return reason;
  }
}
