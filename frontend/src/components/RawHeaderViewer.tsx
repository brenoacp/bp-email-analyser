import React, { useState, useMemo } from 'react';
import {
  Search,
  Copy,
  Check,
  WrapText,
  Download,
  Hash,
  Filter,
  X,
} from 'lucide-react';

interface RawHeaderViewerProps {
  rawHeader: string;
  headerHash?: string;
}

export const RawHeaderViewer: React.FC<RawHeaderViewerProps> = ({ rawHeader, headerHash }) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [isWrapped, setIsWrapped] = useState<boolean>(true);
  const [filterOnlyMatches, setFilterOnlyMatches] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(rawHeader);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([rawHeader], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-header-${(headerHash || 'raw').substring(0, 8)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const lines = useMemo(() => {
    if (!rawHeader) return [];
    return rawHeader.split('\n');
  }, [rawHeader]);

  // Match statistics & filtered lines
  const { filteredLines, matchCount } = useMemo(() => {
    if (!searchTerm.trim()) {
      return {
        filteredLines: lines.map((text, idx) => ({ text, lineNum: idx + 1, hasMatch: false })),
        matchCount: 0,
      };
    }

    const term = searchTerm.toLowerCase();
    let count = 0;
    const items = lines.map((text, idx) => {
      const hasMatch = text.toLowerCase().includes(term);
      if (hasMatch) {
        // Count occurrences in this line
        const regex = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        const matches = text.match(regex);
        count += matches ? matches.length : 1;
      }
      return { text, lineNum: idx + 1, hasMatch };
    });

    return {
      filteredLines: filterOnlyMatches ? items.filter((item) => item.hasMatch) : items,
      matchCount: count,
    };
  }, [lines, searchTerm, filterOnlyMatches]);

  const renderLineContent = (text: string, hasMatch: boolean) => {
    if (!searchTerm.trim() || !hasMatch) {
      // Syntax highlight header name if line starts with 'Header-Name:'
      const matchHeader = text.match(/^([A-Za-z0-9-]+):(.*)$/);
      if (matchHeader) {
        return (
          <>
            <span className="text-sky-600 dark:text-sky-400 font-semibold">{matchHeader[1]}:</span>
            <span className="text-slate-700 dark:text-slate-300">{matchHeader[2]}</span>
          </>
        );
      }
      return <span className="text-slate-700 dark:text-slate-300">{text}</span>;
    }

    // Highlighting search matches
    const term = searchTerm.toLowerCase();
    const parts: React.ReactNode[] = [];
    let remaining = text;
    let keyIdx = 0;

    while (remaining.length > 0) {
      const lower = remaining.toLowerCase();
      const matchIndex = lower.indexOf(term);
      if (matchIndex === -1) {
        parts.push(<span key={keyIdx++} className="text-slate-700 dark:text-slate-300">{remaining}</span>);
        break;
      }

      if (matchIndex > 0) {
        parts.push(<span key={keyIdx++} className="text-slate-700 dark:text-slate-300">{remaining.substring(0, matchIndex)}</span>);
      }

      parts.push(
        <mark
          key={keyIdx++}
          className="bg-amber-400 text-slate-950 font-bold px-0.5 rounded"
        >
          {remaining.substring(matchIndex, matchIndex + term.length)}
        </mark>
      );

      remaining = remaining.substring(matchIndex + term.length);
    }

    return <>{parts}</>;
  };

  return (
    <div className="space-y-4">
      {/* Barra de Ferramentas Superior */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm">
        {/* Campo de Busca */}
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filtrar por cabeçalho, IP, domínio ou termo..."
            className="w-full bg-slate-50 dark:bg-slate-950 text-xs text-slate-800 dark:text-slate-200 pl-9 pr-8 py-2 rounded-xl border border-slate-200 dark:border-slate-800 focus:outline-none focus:border-sky-500 placeholder:text-slate-400 dark:placeholder:text-slate-600 font-mono"
          />
          {searchTerm && (
            <button
              type="button"
              onClick={() => setSearchTerm('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Estatísticas de Busca e Opções */}
        <div className="flex flex-wrap items-center gap-2">
          {searchTerm && (
            <div className="flex items-center gap-2 mr-2">
              <span className="text-xs font-mono text-amber-600 dark:text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded-lg border border-amber-500/20">
                {matchCount} {matchCount === 1 ? 'ocorrência' : 'ocorrências'}
              </span>
              <button
                type="button"
                onClick={() => setFilterOnlyMatches(!filterOnlyMatches)}
                className={`flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border transition-colors ${
                  filterOnlyMatches
                    ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30 font-semibold'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
                title="Mostrar apenas as linhas que contêm o termo pesquisado"
              >
                <Filter className="w-3 h-3" />
                <span>{filterOnlyMatches ? 'Filtrado' : 'Todas as Linhas'}</span>
              </button>
            </div>
          )}

          {/* Toggle Quebra de Linha */}
          <button
            type="button"
            onClick={() => setIsWrapped(!isWrapped)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
              isWrapped
                ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700'
            }`}
            title="Alternar quebra automática de linha"
          >
            <WrapText className="w-3.5 h-3.5" />
            <span>Quebrar Linhas</span>
          </button>

          {/* Copiar */}
          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium transition-colors"
            title="Copiar cabeçalho bruto completo"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copiado!' : 'Copiar'}</span>
          </button>

          {/* Download */}
          <button
            type="button"
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium transition-colors"
            title="Baixar cabeçalho em arquivo .txt"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Baixar .txt</span>
          </button>
        </div>
      </div>

      {/* Janela de Código / Monospace Viewer */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 overflow-hidden shadow-sm">
        {/* Sub-header com Hash SHA-256 */}
        <div className="flex items-center justify-between px-4 py-2 bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 font-mono">
          <div className="flex items-center gap-2">
            <Hash className="w-3.5 h-3.5 text-slate-400" />
            <span className="truncate max-w-sm sm:max-w-md">
              SHA-256: {headerHash || 'N/A'}
            </span>
          </div>
          <span>
            {filteredLines.length} {filteredLines.length === 1 ? 'linha exibida' : 'linhas exibidas'}
          </span>
        </div>

        {/* Visualizador de Linhas */}
        <div className="p-4 max-h-[550px] overflow-y-auto overflow-x-auto text-xs font-mono select-text leading-relaxed">
          {filteredLines.length === 0 ? (
            <div className="py-8 text-center text-slate-400 dark:text-slate-500 italic">
              Nenhuma linha encontrada correspondente ao termo "{searchTerm}".
            </div>
          ) : (
            <table className="w-full border-collapse">
              <tbody>
                {filteredLines.map((item) => (
                  <tr
                    key={item.lineNum}
                    className={`hover:bg-slate-100 dark:hover:bg-slate-900/50 transition-colors ${
                      item.hasMatch ? 'bg-amber-500/10' : ''
                    }`}
                  >
                    {/* Número da Linha */}
                    <td className="py-0.5 pr-4 pl-1 select-none text-right text-slate-400 dark:text-slate-600 font-mono text-[11px] align-top w-10 border-r border-slate-200 dark:border-slate-800/80">
                      {item.lineNum}
                    </td>

                    {/* Conteúdo da Linha */}
                    <td
                      className={`py-0.5 pl-4 pr-2 align-top ${
                        isWrapped ? 'break-all whitespace-pre-wrap' : 'whitespace-pre'
                      }`}
                    >
                      {renderLineContent(item.text, item.hasMatch)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
