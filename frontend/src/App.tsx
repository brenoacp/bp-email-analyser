import React, { useState } from 'react';
import { Shield, FileDown, AlertCircle, Terminal, Activity } from 'lucide-react';
import { HeaderInput } from './components/HeaderInput';
import { RiskGauge } from './components/RiskGauge';
import { analyzeEmail, fetchSample, exportPdf, downloadBlob } from './services/api';
import { EmailAnalysisResponse, AnalysisOptions, SampleId } from './types/email';

export const App: React.FC = () => {
  const [headerText, setHeaderText] = useState<string>('');
  const [analysis, setAnalysis] = useState<EmailAnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isExportingPdf, setIsExportingPdf] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [options, setOptions] = useState<AnalysisOptions>({
    live_dns: true,
    rdap_lookup: true,
    rbl_check: true,
  });

  const handleAnalyze = async () => {
    if (!headerText.trim()) return;
    setIsLoading(true);
    setError(null);

    try {
      const result = await analyzeEmail(headerText, options);
      setAnalysis(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha inesperada ao analisar cabeçalho');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadSample = async (sampleId: SampleId) => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await fetchSample(sampleId);
      setHeaderText(data.raw_header);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao carregar amostra');
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportPdf = async () => {
    if (!headerText.trim() || !analysis) return;
    setIsExportingPdf(true);

    try {
      const blob = await exportPdf(headerText, options);
      const filename = `relatorio-analise-${analysis.raw_header_hash.substring(0, 8)}.pdf`;
      downloadBlob(blob, filename);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao exportar PDF');
    } finally {
      setIsExportingPdf(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white tracking-wide">
                  Email Header Analyzer
                </h1>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  SOC v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Análise Forense e Detecção de Ameaças em Cabeçalhos de E-mail
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              SOC Engine Online
            </span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Header Input Section */}
        <section>
          <HeaderInput
            value={headerText}
            onChange={setHeaderText}
            onAnalyze={handleAnalyze}
            onLoadSample={handleLoadSample}
            isLoading={isLoading}
            options={options}
            onOptionsChange={setOptions}
            onClear={() => {
              setHeaderText('');
              setAnalysis(null);
              setError(null);
            }}
          />
        </section>

        {/* Error Alert */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-semibold">Erro na Operação</p>
              <p className="text-xs text-rose-400 mt-1">{error}</p>
            </div>
          </div>
        )}

        {/* Analysis Status & Preliminary Preview Section */}
        {analysis && (
          <section className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-sky-400" />
                <h2 className="text-lg font-bold text-white">
                  Resultado da Análise Forense
                </h2>
              </div>

              <button
                type="button"
                onClick={handleExportPdf}
                disabled={isExportingPdf}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold shadow transition-colors disabled:opacity-50"
              >
                <FileDown className="w-4 h-4 text-rose-400" />
                {isExportingPdf ? 'Gerando PDF...' : 'Exportar Relatório PDF'}
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Risk Gauge */}
              <div className="md:col-span-1">
                <RiskGauge
                  score={analysis.summary.score}
                  riskLevel={analysis.summary.risk_level}
                  elapsedMs={analysis.summary.elapsed_ms}
                />
              </div>

              {/* Summary Card */}
              <div className="md:col-span-2 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs uppercase tracking-widest text-slate-400 font-semibold">
                      Diagnóstico & Veredito
                    </span>
                    <span className="text-xs font-mono text-slate-500">
                      Hash: {analysis.raw_header_hash.substring(0, 12)}...
                    </span>
                  </div>

                  <h3 className="text-xl font-bold text-white mb-2">
                    {analysis.summary.verdict_text}
                  </h3>

                  <p className="text-sm text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded-xl border border-slate-800/60 font-sans">
                    {analysis.summary.recommendation}
                  </p>
                </div>

                <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-slate-800/80 text-center">
                  <div>
                    <span className="text-[11px] uppercase tracking-wider text-slate-500">Saltos (Hops)</span>
                    <p className="text-lg font-bold text-white mt-0.5">{analysis.summary.total_hops}</p>
                  </div>
                  <div>
                    <span className="text-[11px] uppercase tracking-wider text-slate-500">Achados / Alertas</span>
                    <p className="text-lg font-bold text-sky-400 mt-0.5">{analysis.findings.length}</p>
                  </div>
                  <div>
                    <span className="text-[11px] uppercase tracking-wider text-slate-500">Autenticação SPF</span>
                    <p className="text-lg font-bold uppercase mt-0.5 text-slate-200">
                      {analysis.authentication.spf_verdict}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Empty state when no analysis performed yet */}
        {!analysis && !isLoading && (
          <div className="p-8 rounded-2xl border border-dashed border-slate-800 text-center text-slate-500">
            <Terminal className="w-10 h-10 mx-auto text-slate-600 mb-2" />
            <p className="text-sm font-medium text-slate-400">Nenhum cabeçalho analisado no momento</p>
            <p className="text-xs text-slate-600 mt-1">
              Cole o cabeçalho de um e-mail ou utilize uma das amostras pré-configuradas acima para iniciar a inspeção.
            </p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/60 py-4 text-center text-xs text-slate-500">
        Email Header Analyzer — SOC Cybersecurity Tool
      </footer>
    </div>
  );
};

export default App;
