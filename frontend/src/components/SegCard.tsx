import React from 'react';
import {
  ShieldAlert,
  Cloud,
  Layers,
  Clock,
  AlertTriangle,
  FileX,
  Cpu,
} from 'lucide-react';
import { SegVerdicts, ClientMetadata } from '../types/email';

interface SegCardProps {
  seg: SegVerdicts;
  clientMetadata?: ClientMetadata;
}

export const SegCard: React.FC<SegCardProps> = ({ seg, clientMetadata }) => {
  const getSclDetails = (scl: number | null) => {
    if (scl === null) return { text: 'N/A', color: 'text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700', label: 'Não informado' };
    if (scl === -1) return { text: '-1', color: 'text-sky-700 dark:text-sky-300 bg-sky-500/20 border-sky-500/30', label: 'Bypass Interno / Seguro' };
    if (scl >= 0 && scl <= 1) return { text: `${scl}`, color: 'text-emerald-700 dark:text-emerald-300 bg-emerald-500/20 border-emerald-500/30', label: 'Mensagem Legítima (Não-Spam)' };
    if (scl >= 2 && scl <= 4) return { text: `${scl}`, color: 'text-amber-700 dark:text-amber-300 bg-amber-500/20 border-amber-500/30', label: 'Suspeita Leve' };
    if (scl >= 5 && scl <= 6) return { text: `${scl}`, color: 'text-orange-700 dark:text-orange-300 bg-orange-500/20 border-orange-500/30', label: 'Spam Provável' };
    return { text: `${scl}`, color: 'text-rose-700 dark:text-rose-300 bg-rose-500/20 border-rose-500/30', label: 'Spam de Alta Confiança' };
  };

  const sclDetails = getSclDetails(seg.m365_scl);
  const isM365Phishing = seg.m365_cat?.includes('PHSH') || seg.m365_cat?.includes('MALW');
  const hasDangerousAttachments = clientMetadata?.dangerous_attachments && clientMetadata.dangerous_attachments.length > 0;

  return (
    <div className="space-y-6">
      {/* Alerta de Anexo Perigoso */}
      {hasDangerousAttachments && (
        <div className="p-4 sm:p-5 rounded-2xl bg-rose-500/10 border-2 border-rose-500/40 text-rose-900 dark:text-rose-200 flex items-start gap-4 shadow-lg shadow-rose-950/10 dark:shadow-rose-950/30">
          <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-600 dark:text-rose-400 shrink-0">
            <FileX className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-base font-bold text-slate-900 dark:text-white">
                ALERTA DE SEGURANÇA: Anexos com Extensões de Alto Risco / Executáveis
              </h4>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-rose-500 text-white">
                Risco de Malware
              </span>
            </div>
            <p className="text-xs text-rose-800 dark:text-rose-300 mt-1 leading-relaxed">
              Foram declaradas extensões de arquivos executáveis ou vetores de payload perigosos nos cabeçalhos MIME:
            </p>
            <div className="flex flex-wrap gap-2 mt-2">
              {clientMetadata?.dangerous_attachments.map((ext, i) => (
                <span key={i} className="px-2.5 py-1 rounded bg-rose-100 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-600/50 text-xs font-mono font-bold text-rose-900 dark:text-rose-200">
                  {ext}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Alerta de Microsoft 365 Phishing Flag */}
      {isM365Phishing && (
        <div className="p-4 sm:p-5 rounded-2xl bg-rose-500/10 border-2 border-rose-500/40 text-rose-900 dark:text-rose-200 flex items-start gap-4 shadow-sm">
          <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-600 dark:text-rose-400 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h4 className="text-base font-bold text-slate-900 dark:text-white">
              Veredito Microsoft 365 Forefront: Flag Explícita de Ameaça ({seg.m365_cat})
            </h4>
            <p className="text-xs text-rose-800 dark:text-rose-300 mt-1">
              O mecanismo de proteção do Office 365 / Exchange Online classificou categoricamente este e-mail como phishing ou vetor de distribuição de malware (CAT: {seg.m365_cat}).
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Card Microsoft 365 / Forefront Antispam */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2 text-sky-500 dark:text-sky-400">
                <Cloud className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                  Microsoft 365 / Exchange Antispam
                </span>
              </div>
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-sky-500/20 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                X-Forefront-Antispam
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              {/* SCL */}
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300 block">SCL (Spam Confidence Level)</span>
                  <span className="text-[11px] text-slate-500">{sclDetails.label}</span>
                </div>
                <span className={`text-sm font-bold font-mono px-2.5 py-1 rounded-lg border ${sclDetails.color}`}>
                  {sclDetails.text}
                </span>
              </div>

              {/* BCL */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/60">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300 block">BCL (Bulk Complaint Level)</span>
                  <span className="text-[11px] text-slate-500">Índice de envio em massa (0 a 9)</span>
                </div>
                <span className="text-xs font-bold font-mono px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  {seg.m365_bcl !== null ? seg.m365_bcl : 'N/A'}
                </span>
              </div>

              {/* CAT */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/60">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300 block">CAT (Categoria de Ameaça)</span>
                  <span className="text-[11px] text-slate-500">Classificação forense Forefront</span>
                </div>
                <span
                  className={`text-xs font-bold font-mono px-2.5 py-1 rounded-lg border ${
                    isM365Phishing
                      ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/30'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700'
                  }`}
                >
                  {seg.m365_cat || 'Nenhuma'}
                </span>
              </div>

              {/* SFV */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/60">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300 block">SFV (Spam Filtering Verdict)</span>
                  <span className="text-[11px] text-slate-500">Decisão final do motor de filtragem</span>
                </div>
                <span className="text-xs font-bold font-mono px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  {seg.m365_sfv || 'N/A'}
                </span>
              </div>

              {/* Exchange AuthAs */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/60">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300 block">Exchange AuthAs</span>
                  <span className="text-[11px] text-slate-500">X-MS-Exchange-Organization-AuthAs</span>
                </div>
                <span
                  className={`text-xs font-bold px-2 py-0.5 rounded border ${
                    seg.exchange_auth_as?.toLowerCase() === 'internal'
                      ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700'
                  }`}
                >
                  {seg.exchange_auth_as || 'N/A'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800/60 text-[11px] text-slate-500">
            Decodificação dos marcadores de segurança nativos da nuvem Microsoft Exchange Online.
          </div>
        </div>

        {/* Gateways Corporativos, Sandboxes e Google Workspace */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2 text-purple-500 dark:text-purple-400">
                <Layers className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                  Gateways de Segurança & Sandboxes
                </span>
              </div>
              <span
                className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                  seg.sandbox_detected
                    ? 'bg-purple-500/20 text-purple-700 dark:text-purple-300 border-purple-500/30'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                }`}
              >
                {seg.sandbox_detected ? 'Detectado' : 'Não Detectado'}
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                  SEGs e Mecanismos Detectados:
                </span>
                {seg.sandbox_detected && seg.sandbox_names.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {seg.sandbox_names.map((name, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded bg-purple-500/10 border border-purple-500/20 text-purple-700 dark:text-purple-300 text-xs font-medium"
                      >
                        {name}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500 italic text-xs">
                    Nenhum gateway corporativo (Proofpoint, Defender Safe Links, Mimecast) identificado nos cabeçalhos.
                  </p>
                )}
              </div>

              {/* Google Workspace */}
              {(seg.google_smtp_source || seg.google_message_state) && (
                <div className="pt-3 border-t border-slate-200 dark:border-slate-800/60 space-y-2">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                    Marcadores Google Workspace:
                  </span>
                  {seg.google_smtp_source && (
                    <div className="p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-700 dark:text-slate-300">
                      <span className="text-slate-500">X-Google-Smtp-Source: </span>
                      <span className="text-sky-600 dark:text-sky-400 break-all">{seg.google_smtp_source}</span>
                    </div>
                  )}
                  {seg.google_message_state && (
                    <div className="p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-700 dark:text-slate-300">
                      <span className="text-slate-500">X-Gm-Message-State: </span>
                      <span className="text-slate-600 dark:text-slate-400 break-all">{seg.google_message_state}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800/60 text-[11px] text-slate-500">
            Identifica se o e-mail passou por sandboxes de URL/anexo ou gateways avançados de correio.
          </div>
        </div>
      </div>

      {/* Metadados Adicionais do Cliente (MUA e Message-ID) */}
      {clientMetadata && (
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 shadow-md backdrop-blur-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
            <Cpu className="w-4 h-4 text-sky-500 dark:text-sky-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider">Metadados do Cliente Emissor & Message-ID</h4>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-xs">
            {/* Cliente / X-Mailer */}
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/60">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                Cliente / X-Mailer:
              </span>
              <span className="font-mono text-slate-800 dark:text-slate-200 block break-all">
                {clientMetadata.x_mailer || clientMetadata.user_agent || <span className="text-slate-400 dark:text-slate-500 italic">Não informado</span>}
              </span>
              {clientMetadata.suspicious_client && (
                <span className="mt-2 inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30">
                  <AlertTriangle className="w-3 h-3" /> Cliente Suspeito / Script
                </span>
              )}
            </div>

            {/* Message-ID */}
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/60">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                Message-ID RFC 5322:
              </span>
              <span className="font-mono text-slate-800 dark:text-slate-200 block break-all text-[11px]">
                {clientMetadata.message_id || <span className="text-slate-400 dark:text-slate-500 italic">Ausente</span>}
              </span>
              <div className="mt-2 flex items-center gap-1.5">
                <span
                  className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                    clientMetadata.message_id_valid
                      ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                      : 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/30'
                  }`}
                >
                  {clientMetadata.message_id_valid ? 'Sintaxe Válida' : 'Formato Malformado'}
                </span>
                {clientMetadata.message_id_domain && (
                  <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate" title={clientMetadata.message_id_domain}>
                    @{clientMetadata.message_id_domain}
                  </span>
                )}
              </div>
            </div>

            {/* Descompasso Temporal */}
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/60">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                Descompasso Temporal (Time Drift):
              </span>
              <div className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                <span className="font-mono text-slate-800 dark:text-slate-200">
                  {Math.abs(clientMetadata.time_drift_seconds)}s ({Math.round(Math.abs(clientMetadata.time_drift_seconds) / 60)}min)
                </span>
              </div>
              <div className="mt-2">
                <span
                  className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                    clientMetadata.time_drift_suspicious
                      ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/30'
                      : 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                  }`}
                >
                  {clientMetadata.time_drift_suspicious ? 'Drift Suspeito (> 2h)' : 'Horário Consistente'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
