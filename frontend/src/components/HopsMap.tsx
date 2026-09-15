import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { HopInfo } from '../types/email';
import { MapPin } from 'lucide-react';

interface HopsMapProps {
  hops: HopInfo[];
  isDarkMode?: boolean;
}

const escapeHtml = (str: string): string =>
  str.replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m] || m));

export const HopsMap: React.FC<HopsMapProps> = ({ hops, isDarkMode }) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const leafletInstance = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapRef.current) return;
    if (leafletInstance.current) {
      leafletInstance.current.remove();
      leafletInstance.current = null;
    }

    const map = L.map(mapRef.current).setView([20, 0], 2);
    leafletInstance.current = map;

    const isDark = isDarkMode ?? document.documentElement.classList.contains('dark');
    const baseTile = isDark
      ? 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}'
      : 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}';
    const refTile = isDark
      ? 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}'
      : 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Reference/MapServer/tile/{z}/{y}/{x}';

    L.tileLayer(baseTile, {
      attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
      maxZoom: 16,
    }).addTo(map);

    L.tileLayer(refTile, {
      maxZoom: 16,
    }).addTo(map);

    const validHops = hops.filter(
      (h) => h.latitude !== null && h.longitude !== null && typeof h.latitude === 'number' && typeof h.longitude === 'number'
    );
    const latLngs: L.LatLngExpression[] = [];

    validHops.forEach((h) => {
      if (h.latitude !== null && h.longitude !== null) {
        const pt: [number, number] = [h.latitude, h.longitude];
        latLngs.push(pt);
        const markerColor = h.fcrdns_passed ? '#10b981' : h.fcrdns_passed === false ? '#f43f5e' : '#0284c7';
        const safeIp = h.ip ? escapeHtml(h.ip) : 'N/A';
        const safeCity = h.city ? escapeHtml(h.city) : '';
        const safeCountry = h.country ? escapeHtml(h.country) : '';
        const location = safeCity && safeCountry ? `${safeCity}, ${safeCountry}` : safeCity || safeCountry || 'N/D';
        const rawOrg = h.org || h.asn || '';
        const safeOrg = rawOrg ? escapeHtml(rawOrg) : 'N/D';
        const fcrdnsLabel = h.fcrdns_passed ? 'Válido' : h.fcrdns_passed === false ? 'Inválido' : 'N/A';

        L.circleMarker(pt, {
          radius: 7,
          color: markerColor,
          fillColor: markerColor,
          fillOpacity: 0.85,
          weight: 2,
        })
          .bindPopup(
            `<div style="font-family: sans-serif; font-size: 12px; color: #0f172a; line-height: 1.4;">
              <b style="color: #0284c7;">Salto #${h.order}</b><br/>
              <b>IP:</b> ${safeIp}<br/>
              <b>Local:</b> ${location}<br/>
              <b>Org:</b> ${safeOrg}<br/>
              <b>FCrDNS:</b> ${fcrdnsLabel}
            </div>`
          )
          .addTo(map);
      }
    });

    if (latLngs.length > 1) {
      L.polyline(latLngs, { color: isDark ? '#38bdf8' : '#0284c7', weight: 2.5, dashArray: '5, 8', opacity: 0.85 }).addTo(map);
      map.fitBounds(L.latLngBounds(latLngs), { padding: [40, 40] });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
    }

    return () => {
      map.remove();
      leafletInstance.current = null;
    };
  }, [hops, isDarkMode]);

  const hasCoordinates = hops.some((h) => h.latitude !== null && h.longitude !== null);

  return (
    <div className="relative w-full h-80 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 shadow-inner">
      <div ref={mapRef} className="w-full h-full z-0" />
      {!hasCoordinates && (
        <div className="absolute inset-0 bg-white/85 dark:bg-slate-950/85 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10">
          <div className="p-3 rounded-full bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-400 dark:text-slate-500 mb-2">
            <MapPin className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-slate-800 dark:text-slate-300">Geolocalização indisponível para este trajeto</p>
          <p className="text-xs text-slate-500 mt-1 max-w-md">
            Os saltos identificados pertencem a redes privadas internas (RFC 1918) ou não possuem coordenadas geográficas mapeadas.
          </p>
        </div>
      )}
    </div>
  );
};
