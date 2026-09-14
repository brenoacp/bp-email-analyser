import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Mail,
  User,
  CornerDownRight,
  Send,
} from 'lucide-react';
import { IdentityAnalysis } from '../types/email';

interface IdentityCardProps {
  identity: IdentityAnalysis;
}

export const IdentityCard: React.FC<IdentityCardProps> = ({ identity }) => {
  return (
    <div className="space-y-6">
      {/* Alertas Críticos de BEC e Typosquatting */}
      {identity.display_name_spoofing && (
        <div className="p-4 sm:p-5 rounded-2xl bg-rose-500/10 border-2 border-rose-500/40 text-rose-200 flex items-start gap-4 shadow-lg shadow-rose-950/30">
          <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-base font-bold text-white">
                ALERTA CRÍTICO: Display Name Spoofing Detectado (Ataque BEC / CEO Fraud)
              </h4>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-rose-500 text-white">
                Severidade Máxima
              </span>
            </div>
            <p className="text-xs text-rose-300 mt-1.5 leading-relaxed">
              O remetente utiliza o nome de exibição de uma autoridade, executivo ou departamento sensível (ex:{' '}
              <strong className="text-white font-semibold">"{identity.from_display_name}"</strong>), porém o endereço real
              pertence a um provedor externo ou gratuito (<code className="bg-rose-950/60 px-1 py-0.5 rounded text-white">{identity.from_address}</code>).
            </p>
          </div>
        </div>
      )}

      {identity.typosquatting_detected && (
        <div className="p-4 sm:p-5 rounded-2xl bg-amber-500/10 border-2 border-amber-500/40 text-amber-200 flex items-start gap-4 shadow-lg shadow-amber-950/30">
          <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-400 shrink-0">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-base font-bold text-white">
                ALERTA DE SEGURANÇA: Typosquatting / Homóglifo Detectado
              </h4>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-amber-500 text-slate-950">
                Atenção
              </span>
            </div>
            <p className="text-xs text-amber-300 mt-1.5 leading-relaxed">
              Existe forte similaridade léxica ou troca de caracteres entre o domínio do remetente (
              <code className="bg-amber-950/60 px-1 py-0.5 rounded text-white">{identity.from_domain}</code>) e o domínio de resposta Reply-To (
              <code className="bg-amber-950/60 px-1 py-0.5 rounded text-white">{identity.reply_to_domain || 'N/A'}</code>). Isso é característico de golpes de redirecionamento de faturas ou credenciais.
            </p>
          </div>
        </div>
      )}

      {/* Cartões de Auditoria de Cabeçalhos de Remetente */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* From (Cabeçalho Visível RFC 5322) */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-sky-400">
                <User className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">From: (RFC 5322)</span>
              </div>
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                Visível ao Usuário
              </span>
            </div>

            <div className="mt-4 space-y-2">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Nome de Exibição:
                </span>
                <span className="text-sm font-bold text-white block">
                  {identity.from_display_name || <span className="text-slate-500 italic">Sem nome definido</span>}
                </span>
              </div>

              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Endereço de E-mail:
                </span>
                <span className="text-xs font-mono text-slate-200 block break-all">
                  {identity.from_address}
                </span>
              </div>

              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Domínio Extraído:
                </span>
                <span className="text-xs font-mono font-semibold text-sky-400 block">
                  {identity.from_domain}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Endereço exibido no cliente de e-mail do usuário final.
          </div>
        </div>

        {/* Return-Path (Envelope-From RFC 5321) */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400">
                <Send className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Return-Path (RFC 5321)</span>
              </div>
              <span
                className={`inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                  identity.envelope_mismatch
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                }`}
              >
                {identity.envelope_mismatch ? (
                  <>
                    <XCircle className="w-3 h-3" /> Divergente
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-3 h-3" /> Alinhado
                  </>
                )}
              </span>
            </div>

            <div className="mt-4 space-y-2">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Endereço do Envelope:
                </span>
                <span className="text-xs font-mono text-slate-200 block break-all">
                  {identity.return_path || <span className="text-slate-500 italic">Não declarado</span>}
                </span>
              </div>

              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Domínio do Envelope:
                </span>
                <span className="text-xs font-mono font-semibold text-emerald-400 block">
                  {identity.return_path_domain || <span className="text-slate-500 italic">N/D</span>}
                </span>
              </div>

              {identity.envelope_mismatch && (
                <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[11px] mt-2">
                  Divergência entre From e Return-Path (Envelope Mismatch). Comum em serviços legítimos de newsletter, mas também em spoofing.
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Endereço técnico utilizado para notificações de entrega e bounces (Mail From).
          </div>
        </div>

        {/* Reply-To (Destino das Respostas) */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between shadow-md backdrop-blur-sm">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-purple-400">
                <CornerDownRight className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Reply-To</span>
              </div>
              <span
                className={`inline-flex items-center gap-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                  identity.reply_to_mismatch
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                }`}
              >
                {identity.reply_to_mismatch ? (
                  <>
                    <XCircle className="w-3 h-3" /> Redirecionado
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-3 h-3" /> Correspondente
                  </>
                )}
              </span>
            </div>

            <div className="mt-4 space-y-2">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Endereço de Resposta:
                </span>
                <span className="text-xs font-mono text-slate-200 block break-all">
                  {identity.reply_to || <span className="text-slate-400">Mesmo que From ({identity.from_address})</span>}
                </span>
              </div>

              <div>
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold block">
                  Domínio de Resposta:
                </span>
                <span className="text-xs font-mono font-semibold text-purple-400 block">
                  {identity.reply_to_domain || identity.from_domain}
                </span>
              </div>

              {identity.reply_to_mismatch && (
                <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[11px] mt-2">
                  Atenção: Ao responder, a mensagem será enviada para um domínio diferente do remetente visível.
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500">
            Endereço que recebe as respostas quando o destinatário clica em "Responder".
          </div>
        </div>
      </div>

      {/* Se houver cabeçalho Sender declarado */}
      {identity.sender && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Mail className="w-4 h-4 text-sky-400" />
            <span className="text-slate-400">Cabeçalho Sender: (Agente Transmissor):</span>
            <code className="font-mono text-white bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
              {identity.sender}
            </code>
          </div>
          <span className="text-[11px] text-slate-500">Enviado em nome de outro autor</span>
        </div>
      )}
    </div>
  );
};
