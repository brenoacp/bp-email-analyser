import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  HelpCircle,
  MapPin,
  Server,
  Clock,
  Lock,
  Copy,
  Check,
  AlertTriangle,
} from 'lucide-react';
import { HopInfo } from '../types/email';

interface HopsTimelineProps {
  hops: HopInfo[];
}

export const HopsTimeline: React.FC<HopsTimelineProps> = ({ hops }) => {
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  const totalDelaySeconds = hops.reduce((acc, h) => acc + (h.delay_seconds || 0), 0);
  const publicHops = hops.filter((h) => !h.is_private && h.ip);
  const fcrdnsPassedCount = hops.filter((h) => h.fcrdns_passed === true).length;
  const fcrdnsFailedCount = hops.filter((h) => h.fcrdns_passed === false).length;

  if (!hops || hops.length === 0) {
    return (
      <div className="p-8 rounded-2xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 text-center text-slate-500">
        Nenhum cabeçalho Received: identificado.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Resumo Rápido da Cadeia de Trânsito */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm">
          <span className="text-[11px] uppercase tracking-wider text-slate-500 block">Total de Saltos</span>
          <span className="text-lg font-bold text-slate-900 dark:text-white mt-0.5 block">{hops.length} MTAs</span>
        </div>
        <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm">
          <span className="text-[11px] uppercase tracking-wider text-slate-500 block">Latência Acumulada</span>
          <span className="text-lg font-bold text-sky-600 dark:text-sky-400 mt-0.5 block">
            +{totalDelaySeconds}s {totalDelaySeconds >= 60 && `(~${Math.round(totalDelaySeconds / 60)}min)`}
          </span>
        </div>
        <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm">
          <span className="text-[11px] uppercase tracking-wider text-slate-500 block">FCrDNS Válidos</span>
          <span className="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-0.5 block">
            {fcrdnsPassedCount} de {publicHops.length || hops.length}
          </span>
        </div>
        <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm">
          <span className="text-[11px] uppercase tracking-wider text-slate-500 block">Falhas FCrDNS</span>
          <span className={`text-lg font-bold mt-0.5 block ${fcrdnsFailedCount > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-slate-400'}`}>
            {fcrdnsFailedCount}
          </span>
        </div>
      </div>

      {/* Linha do Tempo Cronológica */}
      <div className="relative pl-6 sm:pl-8 border-l-2 border-slate-200 dark:border-slate-800 space-y-6 ml-3 sm:ml-4">
        {hops.map((hop, idx) => {
          const isFirst = idx === 0;
          const isLast = idx === hops.length - 1;
          const isHighLatency = (hop.delay_seconds || 0) > 1800;

          return (
            <div key={`${hop.order}-${idx}`} className="relative group">
              {/* Marcador do Nó na Timeline */}
              <div
                className={`absolute -left-[31px] sm:-left-[39px] top-1.5 w-6 h-6 sm:w-7 sm:h-7 rounded-full flex items-center justify-center text-xs font-bold ring-4 ring-slate-100 dark:ring-slate-950 transition-colors ${
                  isFirst
                    ? 'bg-sky-500 text-white shadow-lg shadow-sky-500/30'
                    : isLast
                    ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/30'
                    : hop.fcrdns_passed === false
                    ? 'bg-rose-500 text-white'
                    : 'bg-slate-200 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
                }`}
              >
                {hop.order}
              </div>

              {/* Card do Salto */}
              <div className="p-4 sm:p-5 rounded-xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-all shadow-md backdrop-blur-sm">
                {/* Cabeçalho do Card */}
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800/80">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                      Salto #{hop.order}
                    </span>
                    {isFirst && (
                      <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-sky-500/20 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                        Origem Inicial
                      </span>
                    )}
                    {isLast && (
                      <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                        Destino / Borda Interna
                      </span>
                    )}
                    {hop.is_private && (
                      <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-500/20 flex items-center gap-1">
                        <Lock className="w-2.5 h-2.5" /> RFC 1918 (Privado)
                      </span>
                    )}
                  </div>

                  {/* Latência e Timestamp */}
                  <div className="flex items-center gap-3 text-xs">
                    {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                      <span
                        className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium ${
                          isHighLatency
                            ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30'
                            : 'bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700/60'
                        }`}
                        title={isHighLatency ? 'Latência elevada detectada (>30min)' : 'Tempo de trânsito em relação ao salto anterior'}
                      >
                        <Clock className="w-3 h-3 text-slate-400" />
                        +{hop.delay_seconds}s
                        {isHighLatency && <AlertTriangle className="w-3 h-3 text-rose-500 dark:text-rose-400 ml-1" />}
                      </span>
                    )}
                  </div>
                </div>

                {/* Hosts Envolvidos: From / By */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/60">
                    <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-0.5">
                      From (Remetente declarado)
                    </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 break-all">
                      {hop.from_host || <span className="text-slate-400 dark:text-slate-600 italic">Não informado</span>}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/60">
                    <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-0.5">
                      By (Receptor intermediário)
                    </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 break-all">
                      {hop.by_host || <span className="text-slate-400 dark:text-slate-600 italic">Não informado</span>}
                    </span>
                  </div>
                </div>

                {/* Endereço IP & FCrDNS */}
                <div className="flex flex-wrap items-center justify-between gap-3 mt-3 pt-3 border-t border-slate-200 dark:border-slate-800/60">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">IP:</span>
                    {hop.ip ? (
                      <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-950 px-2.5 py-1 rounded-md border border-slate-200 dark:border-slate-800 text-xs font-mono text-sky-600 dark:text-sky-400">
                        <span>{hop.ip}</span>
                        <button
                          type="button"
                          onClick={() => handleCopyIp(hop.ip!)}
                          className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors p-0.5"
                          title="Copiar IP"
                        >
                          {copiedIp === hop.ip ? (
                            <Check className="w-3 h-3 text-emerald-500 dark:text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400 dark:text-slate-600 italic">Sem IP extraído</span>
                    )}

                    {/* FCrDNS Badge */}
                    {hop.fcrdns_passed === true && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" />
                        FCrDNS Válido
                        {hop.fcrdns_hostname && (
                          <span className="text-[10px] font-mono opacity-80 max-w-[150px] truncate" title={hop.fcrdns_hostname}>
                            ({hop.fcrdns_hostname})
                          </span>
                        )}
                      </span>
                    )}
                    {hop.fcrdns_passed === false && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">
                        <XCircle className="w-3.5 h-3.5 text-rose-500 dark:text-rose-400" />
                        FCrDNS Falhou
                        {hop.fcrdns_hostname ? (
                          <span className="text-[10px] font-mono opacity-80 max-w-[150px] truncate" title={hop.fcrdns_hostname}>
                            ({hop.fcrdns_hostname})
                          </span>
                        ) : (
                          <span className="text-[10px] opacity-80">(Sem PTR)</span>
                        )}
                      </span>
                    )}
                    {hop.fcrdns_passed === null && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-slate-100 text-slate-600 border border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700">
                        <HelpCircle className="w-3 h-3" />
                        FCrDNS N/A
                      </span>
                    )}
                  </div>

                  {/* Geo & Org / ASN */}
                  <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
                    {(hop.city || hop.country) && (
                      <span className="flex items-center gap-1">
                        <MapPin className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                        <span>{hop.city ? `${hop.city}, ` : ''}{hop.country}</span>
                      </span>
                    )}
                    {(hop.asn || hop.org) && (
                      <span className="flex items-center gap-1 text-slate-600 dark:text-slate-400" title={hop.org || hop.asn || ''}>
                        <Server className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                        <span className="max-w-[200px] truncate">
                          {hop.asn ? `${hop.asn} ` : ''}{hop.org ? `(${hop.org})` : ''}
                        </span>
                      </span>
                    )}
                  </div>
                </div>

                {/* Timestamp formatado */}
                {hop.timestamp && (
                  <div className="mt-2 text-[11px] text-slate-400 dark:text-slate-500 font-mono">
                    Timestamp: {hop.timestamp}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
