import { FileSearch } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Header } from "./components/Header";
import { ProgressLog } from "./components/ProgressLog";
import { ResultDashboard } from "./components/ResultDashboard";
import { ScanForm } from "./components/ScanForm";
import { startScan, type DoneEvent, type ScanParams } from "./lib/api";

type Status = "idle" | "running" | "done" | "error";

export default function App() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Status>("idle");
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<DoneEvent | null>(null);

  const run = (params: ScanParams) => {
    setStatus("running");
    setLogs([]);
    setResult(null);
    startScan(params, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
      onDone: (done) => {
        setResult(done);
        setStatus(done.ok ? "done" : "error");
      },
      onError: () => setStatus((s) => (s === "running" ? "error" : s)),
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container py-8">
        <div className="grid gap-6 lg:grid-cols-[minmax(320px,380px)_1fr]">
          <ScanForm running={status === "running"} onRun={run} />

          <div className="space-y-6">
            {status === "idle" && (
              <div className="flex min-h-[420px] flex-col items-center justify-center rounded-lg border border-dashed bg-card/40 p-10 text-center animate-fade-in">
                <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-muted text-muted-foreground">
                  <FileSearch className="h-6 w-6" />
                </div>
                <p className="max-w-xs text-sm text-muted-foreground">
                  {t("progress.waiting")}
                </p>
              </div>
            )}

            {status !== "idle" && (
              <>
                {result && <ResultDashboard result={result} />}
                <ProgressLog logs={logs} status={status} />
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
