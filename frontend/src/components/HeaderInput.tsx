import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import {
  Upload,
  FileText,
  Play,
  RotateCcw,
  Loader2,
  AlertTriangle,
  Globe,
  Database,
  Search,
  Info,
} from 'lucide-react';
import { AnalysisOptions } from '../types/email';

export interface HeaderInputProps {
  value: string;
  onChange: (val: string) => void;
  onAnalyze: () => void;
  isLoading?: boolean;
  options?: AnalysisOptions;
  onOptionsChange?: (options: AnalysisOptions) => void;
  onClear?: () => void;
}

export const HeaderInput: React.FC<HeaderInputProps> = ({
  value,
  onChange,
  onAnalyze,
  isLoading = false,
  options = { live_dns: true, rdap_lookup: true, rbl_check: true },
  onOptionsChange,
  onClear,
}) => {
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragError, setDragError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const processFile = (file: File) => {
    setDragError(null);
    const validExtensions = ['.eml', '.msg', '.txt'];
    const fileName = file.name.toLowerCase();
    const hasValidExt = validExtensions.some(ext => fileName.endsWith(ext));

    if (!hasValidExt && file.type && !file.type.startsWith('text/')) {
      setDragError('Por favor, carregue um arquivo .eml, .msg ou texto plano.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result;
      if (typeof content === 'string') {
        onChange(content);
      }
    };
    reader.onerror = () => {
      setDragError('Erro ao ler arquivo selecionado.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      processFile(file);
    }
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
    e.target.value = '';
  };

  const handleOptionToggle = (key: keyof AnalysisOptions) => {
    if (onOptionsChange) {
      onOptionsChange({
        ...options,
        [key]: !options[key],
      });
    }
  };

  const lineCount = value ? value.split('\n').length : 0;
  const charCount = value ? value.length : 0;

  return (
    <div className="w-full bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur-sm">
      {/* Header / Title bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-sky-500 dark:text-sky-400" />
            Cabeçalho Bruto do E-mail
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Cole os cabeçalhos RFC 822 / RFC 5322 ou arraste um arquivo (.eml, .msg)
          </p>
        </div>
      </div>

      {/* Drag & Drop zone & Textarea */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative mt-4 rounded-xl border-2 transition-all duration-200 ${
          isDragging
            ? 'border-sky-500 bg-sky-500/10'
            : 'border-slate-200 dark:border-slate-800/80 bg-slate-50 dark:bg-slate-950/60 focus-within:border-sky-500/60'
        }`}
      >
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Cole os cabeçalhos do e-mail aqui (Received, Authentication-Results, From, To, Date, etc.) ou solte o arquivo .eml..."
          rows={10}
          className="w-full bg-transparent text-slate-800 dark:text-slate-200 text-xs font-mono p-4 resize-y focus:outline-none placeholder:text-slate-400 dark:placeholder:text-slate-600 leading-relaxed"
          spellCheck={false}
        />

        {/* Drag Overlay Banner */}
        {isDragging && (
          <div className="absolute inset-0 bg-white/90 dark:bg-slate-950/85 backdrop-blur-xs flex flex-col items-center justify-center rounded-xl pointer-events-none">
            <Upload className="w-12 h-12 text-sky-500 dark:text-sky-400 animate-bounce mb-2" />
            <span className="text-sm font-semibold text-slate-900 dark:text-white">Solte o arquivo .eml / .msg aqui</span>
            <span className="text-xs text-slate-500 dark:text-slate-400">O conteúdo será carregado automaticamente</span>
          </div>
        )}
      </div>

      {/* Error message */}
      {dragError && (
        <div className="mt-2 text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{dragError}</span>
        </div>
      )}

      {/* Supported file formats note */}
      <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
        <Info className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400/80 shrink-0" />
        <span>
          Arquivos <span className="text-slate-700 dark:text-slate-300 font-mono">.eml</span> e cabeçalhos de texto são suportados nativamente. Arquivos <span className="text-slate-700 dark:text-slate-300 font-mono">.msg</span> devem ser exportados como <span className="text-slate-700 dark:text-slate-300 font-mono">.eml</span> ou colados como texto.
        </span>
      </div>

      {/* Sub-bar: stats and actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 mt-3 text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-4">
          <span>{lineCount} linhas</span>
          <span>•</span>
          <span>{charCount.toLocaleString('pt-BR')} caracteres</span>
        </div>

        {/* Upload file button & Clear button */}
        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.msg,.txt"
            onChange={handleFileInputChange}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/80 dark:hover:bg-slate-700/80 text-slate-700 dark:text-slate-300 transition-colors disabled:opacity-50"
          >
            <Upload className="w-3.5 h-3.5" />
            Importar Arquivo (.eml / .msg)
          </button>

          {value && (
            <button
              type="button"
              onClick={onClear ? onClear : () => onChange('')}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200 transition-colors disabled:opacity-50"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Limpar
            </button>
          )}
        </div>
      </div>

      {/* Bottom options and Analyze action */}
      <div className="flex flex-wrap items-center justify-between gap-4 mt-6 pt-4 border-t border-slate-200 dark:border-slate-800">
        {/* Enrichment Options Toggles */}
        <div className="flex flex-wrap items-center gap-4 text-xs text-slate-700 dark:text-slate-300">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={options.live_dns ?? true}
              onChange={() => handleOptionToggle('live_dns')}
              disabled={isLoading}
              className="rounded bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-sky-500 focus:ring-sky-500/20"
            />
            <Search className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400" />
            <span>Consultas DNS ao vivo</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={options.rdap_lookup ?? true}
              onChange={() => handleOptionToggle('rdap_lookup')}
              disabled={isLoading}
              className="rounded bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-sky-500 focus:ring-sky-500/20"
            />
            <Globe className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400" />
            <span>RDAP & Whois</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={options.rbl_check ?? true}
              onChange={() => handleOptionToggle('rbl_check')}
              disabled={isLoading}
              className="rounded bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-sky-500 focus:ring-sky-500/20"
            />
            <Database className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400" />
            <span>Verificação RBL</span>
          </label>
        </div>

        {/* Primary Action Button */}
        <button
          type="button"
          onClick={onAnalyze}
          disabled={isLoading || !value.trim()}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white font-semibold text-sm shadow-lg shadow-sky-500/20 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed active:scale-98"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Analisando...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-white" />
              <span>Analisar Cabeçalho</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
