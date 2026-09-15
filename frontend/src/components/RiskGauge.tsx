import React, { useEffect, useState, useId } from 'react';
import { RiskLevel } from '../types/email';

interface RiskGaugeProps {
  score: number;
  riskLevel: RiskLevel;
  elapsedMs: number;
}

interface ScoreTheme {
  primary: string;
  gradientStart: string;
  gradientEnd: string;
  glowShadow: string;
  badgeBg: string;
  badgeBorder: string;
  badgeText: string;
  borderClass: string;
  bgGlowClass: string;
  statusLabel: string;
}

function getScoreTheme(score: number, riskLevel: RiskLevel): ScoreTheme {
  if (riskLevel === 'CRITICAL' || score > 75) {
    return {
      primary: '#ef4444',
      gradientStart: '#f43f5e',
      gradientEnd: '#b91c1c',
      glowShadow: '0 0 22px rgba(239, 68, 68, 0.55)',
      badgeBg: 'bg-rose-50 dark:bg-rose-950/40',
      badgeBorder: 'border-rose-300 dark:border-rose-800',
      badgeText: 'text-rose-700 dark:text-rose-400',
      borderClass: 'border-rose-500/40 hover:border-rose-500/70',
      bgGlowClass: 'from-rose-500/15 via-transparent to-transparent',
      statusLabel: 'Ameaça Crítica',
    };
  }

  if (riskLevel === 'HIGH' || score > 50) {
    return {
      primary: '#f97316',
      gradientStart: '#fb923c',
      gradientEnd: '#ea580c',
      glowShadow: '0 0 18px rgba(249, 115, 22, 0.5)',
      badgeBg: 'bg-orange-50 dark:bg-orange-950/40',
      badgeBorder: 'border-orange-300 dark:border-orange-800',
      badgeText: 'text-orange-700 dark:text-orange-400',
      borderClass: 'border-orange-500/35 hover:border-orange-500/60',
      bgGlowClass: 'from-orange-500/10 via-transparent to-transparent',
      statusLabel: 'Alto Risco',
    };
  }

  if (riskLevel === 'INFO' || score > 25) {
    return {
      primary: '#f59e0b',
      gradientStart: '#fcd34d',
      gradientEnd: '#d97706',
      glowShadow: '0 0 16px rgba(245, 158, 11, 0.45)',
      badgeBg: 'bg-amber-50 dark:bg-amber-950/40',
      badgeBorder: 'border-amber-300 dark:border-amber-800',
      badgeText: 'text-amber-700 dark:text-amber-400',
      borderClass: 'border-amber-500/30 hover:border-amber-500/50',
      bgGlowClass: 'from-amber-500/10 via-transparent to-transparent',
      statusLabel: 'Atenção / Moderado',
    };
  }

  return {
    primary: '#10b981',
    gradientStart: '#34d399',
    gradientEnd: '#059669',
    glowShadow: '0 0 16px rgba(16, 185, 129, 0.45)',
    badgeBg: 'bg-emerald-50 dark:bg-emerald-950/40',
    badgeBorder: 'border-emerald-300 dark:border-emerald-800',
    badgeText: 'text-emerald-700 dark:text-emerald-400',
    borderClass: 'border-emerald-500/30 hover:border-emerald-500/50',
    bgGlowClass: 'from-emerald-500/10 via-transparent to-transparent',
    statusLabel: 'Baixo Risco',
  };
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, riskLevel, elapsedMs }) => {
  const [animatedScore, setAnimatedScore] = useState<number>(0);
  const theme = getScoreTheme(score, riskLevel);
  const rawId = useId();
  const gradId = `risk-grad-${rawId.replace(/:/g, '')}`;
  const glowFilterId = `risk-glow-${rawId.replace(/:/g, '')}`;

  // Smooth count-up animation for the score value
  useEffect(() => {
    let startTime: number | null = null;
    const duration = 900;
    const startVal = 0;
    const endVal = Math.max(0, Math.min(100, score));

    let animFrameId: number;
    const step = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min(1, (timestamp - startTime) / duration);
      // Ease out cubic
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(startVal + (endVal - startVal) * easeProgress));

      if (progress < 1) {
        animFrameId = requestAnimationFrame(step);
      }
    };

    animFrameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animFrameId);
  }, [score]);

  const radius = 38;
  const strokeWidth = 8.5;
  const circumference = 2 * Math.PI * radius; // ~238.76
  const strokeDashoffset = circumference - (circumference * animatedScore) / 100;

  // Calculate tip marker position (relative to 0 deg at top since SVG is rotated -90deg)
  const angleRad = (animatedScore / 100) * 2 * Math.PI;
  const tipX = 50 + radius * Math.cos(angleRad);
  const tipY = 50 + radius * Math.sin(angleRad);

  const formattedMs = typeof elapsedMs === 'number' ? elapsedMs.toFixed(1) : elapsedMs;

  return (
    <div
      className={`relative p-6 rounded-2xl bg-white dark:bg-slate-900/90 border ${theme.borderClass} bg-gradient-to-b ${theme.bgGlowClass} backdrop-blur-md flex flex-col items-center justify-center text-center shadow-xl transition-all duration-500 overflow-hidden group`}
      style={{
        boxShadow: `0 10px 30px -10px ${theme.primary}25`,
      }}
    >
      {/* Background ambient lighting pulse */}
      <div
        className="absolute -top-10 -right-10 w-28 h-28 rounded-full blur-3xl pointer-events-none opacity-40 transition-colors duration-700"
        style={{ backgroundColor: theme.primary }}
      />

      {/* Header with live pulse indicator */}
      <div className="flex items-center gap-2 mb-2 z-10">
        <span
          className="w-2 h-2 rounded-full animate-pulse transition-colors duration-500"
          style={{ backgroundColor: theme.primary }}
        />
        <span className="text-xs uppercase tracking-widest text-slate-500 dark:text-slate-400 font-semibold">
          Score de Risco / Fraude
        </span>
      </div>

      {/* Gauge Visualization */}
      <div className="relative flex items-center justify-center w-40 h-40 my-1">
        <svg className="w-full h-full -rotate-90 overflow-visible" viewBox="0 0 100 100">
          <defs>
            <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={theme.gradientStart} />
              <stop offset="100%" stopColor={theme.gradientEnd} />
            </linearGradient>

            <filter id={glowFilterId} x="-30%" y="-30%" width="160%" height="160%">
              <feDropShadow
                dx="0"
                dy="0"
                stdDeviation="3"
                floodColor={theme.primary}
                floodOpacity="0.65"
              />
            </filter>
          </defs>

          {/* Background Track Circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            className="stroke-slate-100 dark:stroke-slate-800/90"
            strokeWidth={strokeWidth}
            fill="transparent"
          />

          {/* Subtle Track Border Inner/Outer Lines */}
          <circle
            cx="50"
            cy="50"
            r={radius + strokeWidth / 2}
            className="stroke-slate-200/50 dark:stroke-slate-800/40"
            strokeWidth="0.5"
            fill="transparent"
          />
          <circle
            cx="50"
            cy="50"
            r={radius - strokeWidth / 2}
            className="stroke-slate-200/50 dark:stroke-slate-800/40"
            strokeWidth="0.5"
            fill="transparent"
          />

          {/* Active Score Gauge Arc with Glow */}
          {animatedScore > 0 && (
            <circle
              cx="50"
              cy="50"
              r={radius}
              stroke={`url(#${gradId})`}
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              filter={`url(#${glowFilterId})`}
              style={{
                transition: 'stroke-dashoffset 0.1s ease-out',
              }}
            />
          )}

          {/* Glowing Tip Marker at the end of the arc */}
          {animatedScore > 1 && (
            <circle
              cx={tipX}
              cy={tipY}
              r={strokeWidth / 2 - 1}
              fill="#ffffff"
              filter={`url(#${glowFilterId})`}
              className="transition-all duration-100"
            />
          )}
        </svg>

        {/* Center Score Numbers */}
        <div className="absolute flex flex-col items-center justify-center select-none pointer-events-none">
          <span
            className="text-4xl sm:text-5xl font-extrabold tracking-tight transition-colors duration-500 drop-shadow-sm"
            style={{ color: theme.primary }}
          >
            {animatedScore}
          </span>
          <span className="text-xs font-semibold text-slate-400 dark:text-slate-500 tracking-wider">
            / 100
          </span>
        </div>
      </div>

      {/* Dynamic Status & Risk Level Badge */}
      <div
        className={`mt-2 px-3 py-1 rounded-full border text-xs font-bold uppercase tracking-wider transition-all duration-500 flex items-center gap-1.5 shadow-sm ${theme.badgeBg} ${theme.badgeBorder} ${theme.badgeText}`}
      >
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{ backgroundColor: theme.primary }}
        />
        <span>{riskLevel}</span>
        <span className="opacity-50">•</span>
        <span className="font-medium text-[11px] lowercase first-letter:uppercase">
          {theme.statusLabel}
        </span>
      </div>

      {/* Latency / Elapsed Time */}
      <span className="text-[11px] text-slate-400 dark:text-slate-500 mt-2 font-mono">
        Processado em {formattedMs}ms
      </span>
    </div>
  );
};

