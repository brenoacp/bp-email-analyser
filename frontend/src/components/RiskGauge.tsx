import React from 'react';
import { RiskLevel } from '../types/email';

interface RiskGaugeProps {
  score: number;
  riskLevel: RiskLevel;
  elapsedMs: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, riskLevel, elapsedMs }) => {
  const getColor = () => {
    switch (riskLevel) {
      case 'SAFE':
        return { bg: 'bg-emerald-500', text: 'text-emerald-500', border: 'border-emerald-500/30' };
      case 'INFO':
        return { bg: 'bg-amber-500', text: 'text-amber-500', border: 'border-amber-500/30' };
      case 'HIGH':
        return { bg: 'bg-orange-500', text: 'text-orange-500', border: 'border-orange-500/30' };
      case 'CRITICAL':
        return { bg: 'bg-rose-600', text: 'text-rose-600', border: 'border-rose-600/30' };
    }
  };

  const colors = getColor();
  const formattedMs = typeof elapsedMs === 'number' ? elapsedMs.toFixed(1) : elapsedMs;

  return (
    <div className={`p-6 rounded-2xl bg-white dark:bg-slate-900/80 border ${colors.border} backdrop-blur-sm flex flex-col items-center justify-center text-center shadow-lg shadow-black/5 dark:shadow-black/20`}>
      <span className="text-xs uppercase tracking-widest text-slate-500 dark:text-slate-400 font-semibold mb-2">
        Score de Risco / Fraude
      </span>
      <div className="relative flex items-center justify-center w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r="40"
            className="stroke-slate-200 dark:stroke-slate-800"
            strokeWidth="10"
            fill="transparent"
          />
          <circle
            cx="50"
            cy="50"
            r="40"
            className={`${colors.text} transition-all duration-1000 ease-out`}
            strokeWidth="10"
            strokeDasharray={251.2}
            strokeDashoffset={251.2 - (251.2 * score) / 100}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className="text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">{score}</span>
          <span className="text-xs text-slate-500 dark:text-slate-400">/ 100</span>
        </div>
      </div>
      <div className={`mt-3 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider text-white ${colors.bg}`}>
        {riskLevel}
      </div>
      <span className="text-xs text-slate-500 mt-2">Processado em {formattedMs}ms</span>
    </div>
  );
};
