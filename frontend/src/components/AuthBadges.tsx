import React, { useState } from 'react';
import {
  ShieldCheck,
  Key,
  Lock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Copy,
  Check,
  Info,
  Code,
} from 'lucide-react';
import { AuthStatus } from '../types/email';

interface AuthBadgesProps {
  auth: AuthStatus;
}

type VerdictStatus = 'pass' | 'warn' | 'fail' | 'neutral';

function categorizeVerdict(verdict: string): VerdictStatus {
  const v = (verdict || '').toLowerCase().trim();
  if (v === 'pass') return 'pass';
  if (v === 'softfail' || v === 'neutral' || v === 'none' || v.includes('temperror')) return 'warn';
  if (v === 'fail' || v === 'permerror' || v === 'invalid' || v === 'reject' || v === 'quarantine') return 'fail';
  return 'neutral';
}

function getVerdictBadge(status: VerdictStatus, text: string) {
  switch (status) {
    case 'pass':
      return {
        badgeClass: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        icon: CheckCircle2,
        label: text.toUpperCase(),
      };
    case 'warn':
      return {
        badgeClass: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        icon: AlertTriangle,
        label: text.toUpperCase(),
      };
    case 'fail':
      return {
        badgeClass: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
        icon: XCircle,
        label: text.toUpperCase(),
      };
    default:
      return {
        badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
        icon: Info,
        label: text.toUpperCase() || 'N/A',
      };
  }
}

export const AuthBadges: React.FC<AuthBadgesProps> = ({ auth }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const spfStatus = categorizeVerdict(auth.spf_verdict);
  const dkimStatus = categorizeVerdict(auth.dkim_verdict);
  const dmarcStatus = categorizeVerdict(auth.dmarc_verdict);
  const arcStatus = categorizeVerdict(auth.arc_verdict);

  const spfBadge = getVerdictBadge(spfStatus, auth.spf_verdict);
  const dkimBadge = getVerdictBadge(dkimStatus, auth.dkim_verdict);
  const dmarcBadge = getVerdictBadge(dmarcStatus, auth.dmarc_verdict);
  const arcBadge = getVerdictBadge(arcStatus, auth.arc_verdict);

  const passesCount = [spfStatus, dkimStatus, dmarcStatus, arcStatus].filter((s) => s === 'pass').length;

  return (
    <div className="space-y-6">
      {/* Resumo de Autenticação */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/90 border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Status Geral de Autenticação Criptográfica</h3>
            <p className="text-xs text-slate-400">
              Validação cruzada de registros DNS públicos e cabeçalhos de autenticação
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Taxa de Conformidade:</span>
          <span
            className={`text-xs font-bold px-2.5 py-1 rounded-full border ${
              passesCount >= 3
                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                : passesCount >= 2
                ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
            }`}
          >
            {passesCount} de 4 Protocolos Aprovados
          </span>
        </div>
      </div>

      {/* Grid com os 4 Cards de Autenticação */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* SPF Card */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-slate-800 text-sky-400">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <span className="text-sm font-bold text-white">SPF</span>
                  <span className="text-[11px] text-slate-500 block">Sender Policy Framework</span>
                </div>
              </div>

              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${spfBadge.badgeClass}`}
              >
                <spfBadge.icon className="w-3.5 h-3.5" />
                {spfBadge.label}
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div className="flex justify-between items-center text-slate-400">
                <span>Veredito:</span>
                <span className="font-semibold text-slate-200 uppercase">{auth.spf_verdict || 'N/A'}</span>
              </div>

              {auth.spf_record ? (
                <div>
                  <div className="flex items-center justify-between mb-1 text-slate-400 text-[11px]">
                    <span className="flex items-center gap-1">
                      <Code className="w-3 h-3 text-sky-400" /> Registro TXT DNS:
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy(auth.spf_record!, 'spf')}
                      className="text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors"
                      title="Copiar registro SPF"
                    >
                      {copiedKey === 'spf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span className="text-[10px]">{copiedKey === 'spf' ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-lg bg-slate-950 text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800/80 break-all whitespace-pre-wrap">
                    {auth.spf_record}
                  </pre>
                </div>
              ) : (
                <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-500 italic text-[11px]">
                  Nenhum registro SPF (v=spf1) encontrado no domínio do remetente.
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Valida se o IP que enviou o e-mail tem autorização explícita do proprietário do domínio.
          </div>
        </div>

        {/* DKIM Card */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-slate-800 text-amber-400">
                  <Key className="w-4 h-4" />
                </div>
                <div>
                  <span className="text-sm font-bold text-white">DKIM</span>
                  <span className="text-[11px] text-slate-500 block">DomainKeys Identified Mail</span>
                </div>
              </div>

              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${dkimBadge.badgeClass}`}
              >
                <dkimBadge.icon className="w-3.5 h-3.5" />
                {dkimBadge.label}
              </span>
            </div>

            <div className="mt-4 space-y-2 text-xs">
              <div className="flex justify-between items-center text-slate-400">
                <span>Veredito:</span>
                <span className="font-semibold text-slate-200 uppercase">{auth.dkim_verdict || 'N/A'}</span>
              </div>

              <div className="flex justify-between items-center text-slate-400">
                <span>Domínio da Assinatura (d=):</span>
                <span className="font-mono text-slate-200">{auth.dkim_domain || 'N/A'}</span>
              </div>

              <div className="flex justify-between items-center text-slate-400">
                <span>Seletor de Chave (s=):</span>
                <span className="font-mono text-slate-200">{auth.dkim_selector || 'N/A'}</span>
              </div>

              {auth.dkim_selector && auth.dkim_domain && (
                <div className="mt-2 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400">
                  <span className="text-slate-500">Host DNS Chave Pública: </span>
                  <span className="text-sky-400">{auth.dkim_selector}._domainkey.{auth.dkim_domain}</span>
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Garante criptograficamente que a mensagem não foi adulterada durante o trânsito.
          </div>
        </div>

        {/* DMARC Card */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-slate-800 text-sky-400">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <span className="text-sm font-bold text-white">DMARC</span>
                  <span className="text-[11px] text-slate-500 block">Domain-based Message Authentication</span>
                </div>
              </div>

              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${dmarcBadge.badgeClass}`}
              >
                <dmarcBadge.icon className="w-3.5 h-3.5" />
                {dmarcBadge.label}
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div className="flex justify-between items-center text-slate-400">
                <span>Veredito:</span>
                <span className="font-semibold text-slate-200 uppercase">{auth.dmarc_verdict || 'N/A'}</span>
              </div>

              <div className="flex justify-between items-center text-slate-400">
                <span>Política Declarada (p=):</span>
                {auth.dmarc_policy ? (
                  <span
                    className={`font-mono font-bold uppercase px-2 py-0.5 rounded text-[10px] ${
                      auth.dmarc_policy.toLowerCase() === 'reject'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : auth.dmarc_policy.toLowerCase() === 'quarantine'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {auth.dmarc_policy}
                  </span>
                ) : (
                  <span className="text-slate-500 italic">Nenhuma política</span>
                )}
              </div>

              {auth.dmarc_record ? (
                <div>
                  <div className="flex items-center justify-between mb-1 text-slate-400 text-[11px]">
                    <span className="flex items-center gap-1">
                      <Code className="w-3 h-3 text-sky-400" /> Registro TXT DMARC:
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy(auth.dmarc_record!, 'dmarc')}
                      className="text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors"
                      title="Copiar registro DMARC"
                    >
                      {copiedKey === 'dmarc' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span className="text-[10px]">{copiedKey === 'dmarc' ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-lg bg-slate-950 text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800/80 break-all whitespace-pre-wrap">
                    {auth.dmarc_record}
                  </pre>
                </div>
              ) : (
                <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-500 italic text-[11px]">
                  Nenhum registro DMARC (_dmarc) configurado no domínio.
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Define como o servidor de destino deve agir quando SPF e DKIM falharem (none, quarantine, reject).
          </div>
        </div>

        {/* ARC Card */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-slate-800 text-purple-400">
                  <Layers className="w-4 h-4" />
                </div>
                <div>
                  <span className="text-sm font-bold text-white">ARC</span>
                  <span className="text-[11px] text-slate-500 block">Authenticated Received Chain</span>
                </div>
              </div>

              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${arcBadge.badgeClass}`}
              >
                <arcBadge.icon className="w-3.5 h-3.5" />
                {arcBadge.label}
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div className="flex justify-between items-center text-slate-400">
                <span>Veredito da Cadeia:</span>
                <span className="font-semibold text-slate-200 uppercase">{auth.arc_verdict || 'N/A'}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-xs leading-relaxed">
                {arcStatus === 'pass' && (
                  <span className="text-emerald-400">
                    Cadeia ARC preservada com sucesso. A autenticação original foi mantida por intermediários legítimos.
                  </span>
                )}
                {arcStatus === 'fail' && (
                  <span className="text-rose-400">
                    Quebra de cadeia ARC detectada. A mensagem pode ter sofrido alterações indevidas em servidores intermediários.
                  </span>
                )}
                {(arcStatus === 'warn' || arcStatus === 'neutral') && (
                  <span className="text-slate-400">
                    Nenhuma cadeia ARC presente ou mensagem entregue sem necessidade de verificação de retransmissor.
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Preserva o resultado das autenticações quando o e-mail transita por listas de discussão ou redirecionamentos.
          </div>
        </div>
      </div>
    </div>
  );
};
