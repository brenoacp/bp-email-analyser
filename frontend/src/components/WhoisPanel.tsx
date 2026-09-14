import React, { useState } from 'react';
import {
  Globe,
  Calendar,
  MapPin,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Lock,
  Radio,
} from 'lucide-react';
import { DomainInfo, OriginIpInfo } from '../types/email';

interface WhoisPanelProps {
  domainInfo: DomainInfo;
  originIp: OriginIpInfo;
}

export const WhoisPanel: React.FC<WhoisPanelProps> = ({ domainInfo, originIp }) => {
  const [copiedIp, setCopiedIp] = useState<boolean>(false);

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 2000);
  };

  const getAgeBadge = (ageDays: number | null) => {
    if (ageDays === null) {
      return {
        badge: 'bg-slate-800 text-slate-400 border-slate-700',
        label: 'Idade Desconhecida',
        description: 'Dados de WHOIS / RDAP indisponíveis para este TLD.',
      };
    }
    if (ageDays < 30) {
      return {
        badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
        label: `${ageDays} dias (Burner Domain - Risco Crítico)`,
        description: 'Domínio criado há menos de 30 dias. Fortíssimo indicador de infraestrutura descartável para golpes.',
      };
    }
    if (ageDays < 90) {
      return {
        badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
        label: `${ageDays} dias (Domínio Recente)`,
        description: 'Domínio registrado há menos de 90 dias. Requer atenção redobrada.',
      };
    }
    return {
      badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      label: `${ageDays} dias (Domínio Maduro)`,
      description: 'Domínio estabelecido e registrado há mais de 3 meses.',
    };
  };

  const ageBadge = getAgeBadge(domainInfo.age_days);

  return (
    <div className="space-y-6">
      {/* Alerta de RBL se o IP de origem estiver listado */}
      {originIp.rbl_listed && (
        <div className="p-4 sm:p-5 rounded-2xl bg-rose-500/10 border-2 border-rose-500/40 text-rose-200 flex items-start gap-4 shadow-lg shadow-rose-950/30">
          <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-base font-bold text-white">
                ALERTA DE REPUTAÇÃO: IP de Origem Listado em Listas Negras (RBL / DNSBL)
              </h4>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-rose-500 text-white">
                Blacklisted
              </span>
            </div>
            <p className="text-xs text-rose-300 mt-1.5 leading-relaxed">
              O endereço IP de origem (<code className="bg-rose-950/80 px-1 py-0.5 rounded text-white font-mono">{originIp.ip}</code>)
              possui histórico ativo de envio de spam, botnet ou tráfego malicioso nas seguintes listas de reputação:
            </p>
            <div className="flex flex-wrap gap-2 mt-2.5">
              {originIp.rbl_listings.map((rbl, idx) => (
                <span key={idx} className="px-3 py-1 rounded-lg bg-rose-950/80 border border-rose-600/50 text-xs font-mono font-bold text-rose-200">
                  {rbl}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Grid Principal: Domínio vs IP de Origem */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Inteligência do Domínio Emissor (WHOIS / RDAP & MX) */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-sky-400">
                <Globe className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Inteligência de Domínio (RDAP / WHOIS)
                </span>
              </div>
              <span className="text-xs font-mono font-bold text-sky-400">
                {domainInfo.domain}
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              {/* Idade do Domínio */}
              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                  Idade do Domínio:
                </span>
                <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${ageBadge.badge}`}>
                  <Calendar className="w-3.5 h-3.5" />
                  {ageBadge.label}
                </span>
                <p className="text-[11px] text-slate-400 mt-1">{ageBadge.description}</p>
              </div>

              {/* Data de Registro */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span className="text-slate-400">Data de Registro:</span>
                <span className="font-mono text-slate-200">
                  {domainInfo.registered_at ? new Date(domainInfo.registered_at).toLocaleDateString('pt-BR') : 'N/D'}
                </span>
              </div>

              {/* Registrar */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span className="text-slate-400">Registrador (Registrar):</span>
                <span className="font-medium text-slate-200 truncate max-w-[200px]" title={domainInfo.registrar || ''}>
                  {domainInfo.registrar || 'Não identificado'}
                </span>
              </div>

              {/* País de Registro */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span className="text-slate-400">País Declarado:</span>
                <span className="font-medium text-slate-200">
                  {domainInfo.country || 'Não informado'}
                </span>
              </div>

              {/* Registros MX */}
              <div className="pt-2 border-t border-slate-800/60">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    Registros MX (Servidores de Correio):
                  </span>
                  <span
                    className={`inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                      domainInfo.has_mx
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                        : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                    }`}
                  >
                    {domainInfo.has_mx ? (
                      <>
                        <CheckCircle2 className="w-3 h-3" /> MX Válido
                      </>
                    ) : (
                      <>
                        <XCircle className="w-3 h-3" /> Sem MX
                      </>
                    )}
                  </span>
                </div>

                {domainInfo.has_mx && domainInfo.mx_records.length > 0 ? (
                  <div className="space-y-1">
                    {domainInfo.mx_records.slice(0, 3).map((mx, idx) => (
                      <div
                        key={idx}
                        className="p-1.5 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-300 truncate"
                        title={mx}
                      >
                        {mx}
                      </div>
                    ))}
                    {domainInfo.mx_records.length > 3 && (
                      <span className="text-[10px] text-slate-500 block text-right">
                        +{domainInfo.mx_records.length - 3} outros servidores MX
                      </span>
                    )}
                  </div>
                ) : (
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-[11px]">
                    Nenhum servidor de recebimento MX localizado. Domínio não pode receber mensagens.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Validação da legitimidade cadastral e capacidade de entrega do domínio.
          </div>
        </div>

        {/* Inteligência do IP de Origem & ASN */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400">
                <Radio className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  IP de Origem & Rede Emissora
                </span>
              </div>
              {originIp.is_private ? (
                <span className="inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  <Lock className="w-3 h-3" /> Rede Privada
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  IP Público
                </span>
              )}
            </div>

            <div className="mt-4 space-y-3 text-xs">
              {/* Endereço IP */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Endereço IP:</span>
                {originIp.ip ? (
                  <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded-md border border-slate-800 font-mono text-emerald-400 font-bold">
                    <span>{originIp.ip}</span>
                    <button
                      type="button"
                      onClick={() => handleCopyIp(originIp.ip!)}
                      className="text-slate-500 hover:text-slate-300 transition-colors p-0.5"
                      title="Copiar IP de Origem"
                    >
                      {copiedIp ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                ) : (
                  <span className="text-slate-500 italic">Não identificado</span>
                )}
              </div>

              {/* Localização */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span className="text-slate-400">Localização Geográfica:</span>
                <span className="font-medium text-slate-200 flex items-center gap-1">
                  <MapPin className="w-3.5 h-3.5 text-slate-500" />
                  {originIp.city ? `${originIp.city}, ` : ''}{originIp.country || 'Desconhecida'}
                </span>
              </div>

              {/* ASN & Organização */}
              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                  Sistema Autônomo (ASN) & Organização / ISP:
                </span>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300">
                  <span className="text-sky-400 font-semibold">{originIp.asn || 'ASN N/D'}</span>
                  {originIp.org && <span className="text-slate-400"> — {originIp.org}</span>}
                </div>
              </div>

              {/* Reputação RBL */}
              <div className="pt-2 border-t border-slate-800/60">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    Reputação em Blacklists (RBL):
                  </span>
                  <span
                    className={`inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                      originIp.rbl_listed
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                        : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                    }`}
                  >
                    {originIp.rbl_listed ? (
                      <>
                        <ShieldAlert className="w-3 h-3 text-rose-400" /> Listado
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-3 h-3 text-emerald-400" /> Limpo
                      </>
                    )}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  {originIp.rbl_listed
                    ? 'Identificado em listas públicas de reputação negativa.'
                    : 'Sem registros maliciosos ativos em Spamhaus, Barracuda ou SpamCop.'}
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Identificação de infraestrutura de rede, país de emissão e reputação global.
          </div>
        </div>
      </div>
    </div>
  );
};
