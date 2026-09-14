import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileDown,
  Code2,
  AlertCircle,
  Terminal,
  Activity,
  MapPin,
  CheckCircle2,
  AlertTriangle,
  Globe,
  FileText,
  UserCheck,
  Cpu,
  Moon,
  Sun,
  Copy,
  Check,
} from 'lucide-react';
import { HeaderInput } from './components/HeaderInput';
import { RiskGauge } from './components/RiskGauge';
import { HopsMap } from './components/HopsMap';
import { HopsTimeline } from './components/HopsTimeline';
import { AuthBadges } from './components/AuthBadges';
import { IdentityCard } from './components/IdentityCard';
import { SegCard } from './components/SegCard';
import { WhoisPanel } from './components/WhoisPanel';
import { RawHeaderViewer } from './components/RawHeaderViewer';
import { analyzeEmail, fetchSample, exportPdf, downloadBlob } from './services/api';
import { EmailAnalysisResponse, AnalysisOptions, SampleId, RiskLevel } from './types/email';

type TabId = 'overview' | 'hops' | 'auth' | 'identity' | 'whois' | 'seg' | 'raw';

export const App: React.FC = () => {
  const [headerText, setHeaderText] = useState<string>('');
  const [analysis, setAnalysis] = useState<EmailAnalysisResponse | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isExportingPdf, setIsExportingPdf] = useState<boolean>(false);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);
  const [options, setOptions] = useState<AnalysisOptions>({
    live_dns: true,
    rdap_lookup: true,
    rbl_check: true,
  });

  // Apply dark mode class to HTML root
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDarkMode]);

  const handleAnalyze = async () => {
    if (!headerText.trim()) return;
    setIsLoading(true);
    setError(null);

    try {
      const result = await analyzeEmail(headerText, options);
      setAnalysis(result);
      setActiveTab('overview');
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
      // Automatically analyze sample on load for fast demonstration
      const result = await analyzeEmail(data.raw_header, options);
      setAnalysis(result);
      setActiveTab('overview');
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

  const handleExportJson = () => {
    if (!analysis) return;
    const jsonStr = JSON.stringify(analysis, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const filename = `analise-forense-${analysis.raw_header_hash.substring(0, 8)}.json`;
    downloadBlob(blob, filename);
  };

  const handleCopyJson = () => {
    if (!analysis) return;
    navigator.clipboard.writeText(JSON.stringify(analysis, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleClear = () => {
    setHeaderText('');
    setAnalysis(null);
    setError(null);
    setActiveTab('overview');
  };

  const getSeverityBadgeClass = (severity: RiskLevel) => {
    switch (severity) {
      case 'SAFE':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
      case 'INFO':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
    }
  };

  const tabs: { id: TabId; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }[] = [
    { id: 'overview', label: 'Visão Geral', icon: Activity, count: analysis?.findings.length },
    { id: 'hops', label: 'Saltos & Rota', icon: MapPin, count: analysis?.hops.length },
    { id: 'auth', label: 'Autenticação', icon: Shield },
    { id: 'identity', label: 'Identidade & BEC', icon: UserCheck },
    { id: 'whois', label: 'Domínio & Whois', icon: Globe },
    { id: 'seg', label: 'Gateways & SEGs', icon: Cpu },
    { id: 'raw', label: 'Cabeçalho Bruto', icon: FileText },
  ];

  return (
    <div className={`min-h-screen flex flex-col transition-colors duration-200 ${isDarkMode ? 'bg-slate-950 text-slate-100' : 'bg-slate-100 text-slate-900'}`}>
      {/* Barra de Navegação Superior do SOC */}
      <header className={`border-b sticky top-0 z-50 backdrop-blur-md transition-colors duration-200 ${
        isDarkMode ? 'border-slate-800/80 bg-slate-900/80' : 'border-slate-300/80 bg-white/85'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 shadow-sm">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className={`text-base font-extrabold tracking-wide ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
                  Email Header Analyzer
                </h1>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-500/30">
                  SOC Edition
                </span>
              </div>
              <p className={`text-xs ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
                Análise Forense e Detecção Avançada de Ameaças em Cabeçalhos RFC 5322
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Status do Motor */}
            <div className={`hidden sm:flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium border ${
              isDarkMode ? 'bg-slate-900 border-slate-800 text-slate-300' : 'bg-slate-200 border-slate-300 text-slate-700'
            }`}>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>SOC Engine Operacional</span>
            </div>

            {/* Alternador Dark / Light Mode */}
            <button
              type="button"
              onClick={() => setIsDarkMode(!isDarkMode)}
              className={`p-2 rounded-xl border transition-colors ${
                isDarkMode
                  ? 'bg-slate-900 border-slate-800 text-amber-400 hover:bg-slate-850'
                  : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-200'
              }`}
              title={isDarkMode ? 'Mudar para tema claro' : 'Mudar para tema escuro'}
            >
              {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </header>

      {/* Conteúdo Principal */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Seção de Entrada do Cabeçalho */}
        <section>
          <HeaderInput
            value={headerText}
            onChange={setHeaderText}
            onAnalyze={handleAnalyze}
            onLoadSample={handleLoadSample}
            isLoading={isLoading}
            options={options}
            onOptionsChange={setOptions}
            onClear={handleClear}
          />
        </section>

        {/* Alerta de Erro */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start gap-3 shadow-lg">
            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-rose-400" />
            <div className="text-sm flex-1">
              <p className="font-semibold text-rose-200">Erro no Processamento</p>
              <p className="text-xs text-rose-300 mt-0.5">{error}</p>
            </div>
            <button
              type="button"
              onClick={() => setError(null)}
              className="text-rose-400 hover:text-rose-200 text-xs font-bold"
            >
              Fechar
            </button>
          </div>
        )}

        {/* Painel Completo de Resultados Forenses */}
        {analysis && (
          <section className="space-y-6">
            {/* Barra de Ações e Exportações */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-md">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-sky-400" />
                <h2 className="text-base font-bold text-white">
                  Diagnóstico Forense Concluído
                </h2>
                <span className="text-xs font-mono text-slate-500 hidden sm:inline">
                  (SHA-256: {analysis.raw_header_hash.substring(0, 10)}...)
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {/* Copiar JSON */}
                <button
                  type="button"
                  onClick={handleCopyJson}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition-colors"
                  title="Copiar estrutura JSON da análise"
                >
                  {copiedJson ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  <span>{copiedJson ? 'Copiado!' : 'Copiar JSON'}</span>
                </button>

                {/* Baixar JSON */}
                <button
                  type="button"
                  onClick={handleExportJson}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition-colors"
                  title="Baixar análise completa em arquivo JSON"
                >
                  <Code2 className="w-4 h-4 text-sky-400" />
                  <span>Baixar JSON</span>
                </button>

                {/* Exportar Relatório PDF */}
                <button
                  type="button"
                  onClick={handleExportPdf}
                  disabled={isExportingPdf}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-600 text-white text-xs font-bold shadow-lg shadow-rose-900/30 transition-all disabled:opacity-50"
                  title="Gerar e exportar relatório técnico completo em PDF para SOC"
                >
                  <FileDown className="w-4 h-4" />
                  <span>{isExportingPdf ? 'Gerando PDF...' : 'Exportar Relatório PDF'}</span>
                </button>
              </div>
            </div>

            {/* Navegação por Abas */}
            <div className="flex border-b border-slate-800 overflow-x-auto gap-2 pb-1 scrollbar-none">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 px-4 py-2.5 rounded-t-xl font-medium text-xs whitespace-nowrap transition-all border-b-2 ${
                      isActive
                        ? 'border-sky-500 text-sky-400 bg-slate-900/80 font-bold'
                        : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.label}</span>
                    {tab.count !== undefined && (
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                          isActive ? 'bg-sky-500/20 text-sky-300' : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {tab.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Conteúdo das Abas */}
            <div className="min-h-[400px]">
              {/* Aba 1: Visão Geral */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Linha Superior: Risk Gauge + Resumo Executivo */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-1">
                      <RiskGauge
                        score={analysis.summary.score}
                        riskLevel={analysis.summary.risk_level}
                        elapsedMs={analysis.summary.elapsed_ms}
                      />
                    </div>

                    <div className="md:col-span-2 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-lg">
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs uppercase tracking-widest text-slate-400 font-semibold">
                            Diagnóstico & Veredito Executivo
                          </span>
                          <span className="text-xs font-mono text-slate-500">
                            Hash: {analysis.raw_header_hash.substring(0, 16)}
                          </span>
                        </div>

                        <h3 className="text-xl font-bold text-white mb-3">
                          {analysis.summary.verdict_text}
                        </h3>

                        <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 text-sm text-slate-300 leading-relaxed font-sans">
                          <strong className="text-white block mb-1">Recomendação de Resposta a Incidentes:</strong>
                          {analysis.summary.recommendation}
                        </div>
                      </div>

                      {/* Métricas Principais */}
                      <div className="grid grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800 text-center">
                        <div>
                          <span className="text-[10px] uppercase tracking-wider text-slate-500 block">Saltos de Rede</span>
                          <span className="text-lg font-bold text-white mt-0.5 block">{analysis.summary.total_hops}</span>
                        </div>
                        <div>
                          <span className="text-[10px] uppercase tracking-wider text-slate-500 block">Achados</span>
                          <span className="text-lg font-bold text-sky-400 mt-0.5 block">{analysis.findings.length}</span>
                        </div>
                        <div>
                          <span className="text-[10px] uppercase tracking-wider text-slate-500 block">SPF</span>
                          <span className="text-lg font-bold uppercase mt-0.5 block text-slate-200">
                            {analysis.authentication.spf_verdict}
                          </span>
                        </div>
                        <div>
                          <span className="text-[10px] uppercase tracking-wider text-slate-500 block">DMARC</span>
                          <span className="text-lg font-bold uppercase mt-0.5 block text-slate-200">
                            {analysis.authentication.dmarc_verdict}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Lista Completa de Achados Técnicos (Findings) */}
                  <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-lg space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-amber-400" />
                        <h4 className="text-base font-bold text-white">
                          Evidências Forenses & Achados ({analysis.findings.length})
                        </h4>
                      </div>
                      <span className="text-xs text-slate-500">
                        Total Ponderado: {analysis.findings.reduce((acc, f) => acc + f.points, 0)} pontos
                      </span>
                    </div>

                    {analysis.findings.length === 0 ? (
                      <div className="p-8 text-center text-slate-500 italic">
                        <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-400 mb-2" />
                        Nenhuma anomalia ou evidência de fraude foi identificada neste cabeçalho.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {analysis.findings.map((f, idx) => (
                          <div
                            key={idx}
                            className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition-colors"
                          >
                            <div className="space-y-1 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${getSeverityBadgeClass(f.severity)}`}>
                                  {f.severity}
                                </span>
                                <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-semibold">
                                  {f.category}
                                </span>
                                <span className="text-xs font-bold text-white">
                                  {f.title}
                                </span>
                              </div>
                              <p className="text-xs text-slate-300 leading-relaxed">
                                {f.description}
                              </p>
                            </div>

                            <div className="shrink-0 flex sm:flex-col items-end justify-between sm:justify-center">
                              <span className="text-xs font-bold font-mono px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                +{f.points} pts
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Aba 2: Saltos & Rota */}
              {activeTab === 'hops' && (
                <div className="space-y-6">
                  {/* Mapa Leaflet */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
                      <MapPin className="w-4 h-4 text-sky-400" />
                      Mapeamento Geográfico da Cadeia de MTAs
                    </h3>
                    <HopsMap hops={analysis.hops} />
                  </div>

                  {/* Linha do Tempo Cronológica */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-sky-400" />
                      Cadeia Cronológica de Saltos (Received:)
                    </h3>
                    <HopsTimeline hops={analysis.hops} />
                  </div>
                </div>
              )}

              {/* Aba 3: Autenticação */}
              {activeTab === 'auth' && (
                <div>
                  <AuthBadges auth={analysis.authentication} />
                </div>
              )}

              {/* Aba 4: Identidade & BEC */}
              {activeTab === 'identity' && (
                <div>
                  <IdentityCard identity={analysis.identity} />
                </div>
              )}

              {/* Aba 5: Domínio & Whois */}
              {activeTab === 'whois' && (
                <div>
                  <WhoisPanel
                    domainInfo={analysis.domain_info}
                    originIp={analysis.origin_ip}
                  />
                </div>
              )}

              {/* Aba 6: Gateways & SEGs */}
              {activeTab === 'seg' && (
                <div>
                  <SegCard
                    seg={analysis.seg_verdicts}
                    clientMetadata={analysis.client_metadata}
                  />
                </div>
              )}

              {/* Aba 7: Cabeçalho Bruto */}
              {activeTab === 'raw' && (
                <div>
                  <RawHeaderViewer
                    rawHeader={headerText}
                    headerHash={analysis.raw_header_hash}
                  />
                </div>
              )}
            </div>
          </section>
        )}

        {/* Estado Inicial Vazio */}
        {!analysis && !isLoading && (
          <div className="p-12 rounded-2xl border-2 border-dashed border-slate-800/80 bg-slate-900/30 text-center text-slate-500 space-y-3">
            <Terminal className="w-12 h-12 mx-auto text-slate-600" />
            <h3 className="text-base font-semibold text-slate-300">Pronto para Inspeção Forense</h3>
            <p className="text-xs text-slate-500 max-w-lg mx-auto leading-relaxed">
              Insira o cabeçalho completo de um e-mail no campo acima, arraste um arquivo <code className="text-slate-400">.eml</code> ou selecione uma das amostras pré-configuradas (Legítimo, Phishing, BEC, Botnet) para executar a desmontagem e análise automatizada.
            </p>
          </div>
        )}
      </main>

      {/* Rodapé */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-500 bg-slate-950/80 mt-auto">
        <p>Email Header Analyzer — Plataforma Forense para Centros de Operações de Segurança (SOC)</p>
      </footer>
    </div>
  );
};

export default App;
