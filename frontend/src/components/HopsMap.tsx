import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { HopInfo } from '../types/email';
import { MapPin } from 'lucide-react';

interface HopsMapProps {
  hops: HopInfo[];
}

export const HopsMap: React.FC<HopsMapProps> = ({ hops }) => {
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

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; CartoDB &copy; OpenStreetMap',
      maxZoom: 19,
    }).addTo(map);

    const validHops = hops.filter(
      (h) => h.latitude !== null && h.longitude !== null && typeof h.latitude === 'number' && typeof h.longitude === 'number'
    );
    const latLngs: L.LatLngExpression[] = [];

    validHops.forEach((h) => {
      if (h.latitude !== null && h.longitude !== null) {
        const pt: [number, number] = [h.latitude, h.longitude];
        latLngs.push(pt);
        const markerColor = h.fcrdns_passed ? '#10b981' : h.fcrdns_passed === false ? '#f43f5e' : '#38bdf8';
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
              <b>IP:</b> ${h.ip || 'N/A'}<br/>
              <b>Local:</b> ${h.city || ''}${h.city && h.country ? ', ' : ''}${h.country || 'N/D'}<br/>
              <b>Org:</b> ${h.org || h.asn || 'N/D'}<br/>
              <b>FCrDNS:</b> ${h.fcrdns_passed ? 'Válido' : h.fcrdns_passed === false ? 'Inválido' : 'N/A'}
            </div>`
          )
          .addTo(map);
      }
    });

    if (latLngs.length > 1) {
      L.polyline(latLngs, { color: '#38bdf8', weight: 2.5, dashArray: '5, 8', opacity: 0.8 }).addTo(map);
      map.fitBounds(L.latLngBounds(latLngs), { padding: [40, 40] });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
    }

    return () => {
      map.remove();
      leafletInstance.current = null;
    };
  }, [hops]);

  const hasCoordinates = hops.some((h) => h.latitude !== null && h.longitude !== null);

  return (
    <div className="relative w-full h-80 rounded-xl overflow-hidden border border-slate-800 bg-slate-950 shadow-inner">
      <div ref={mapRef} className="w-full h-full z-0" />
      {!hasCoordinates && (
        <div className="absolute inset-0 bg-slate-950/85 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10">
          <div className="p-3 rounded-full bg-slate-900 border border-slate-800 text-slate-500 mb-2">
            <MapPin className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-slate-300">Geolocalização indisponível para este trajeto</p>
          <p className="text-xs text-slate-500 mt-1 max-w-md">
            Os saltos identificados pertencem a redes privadas internas (RFC 1918) ou não possuem coordenadas geográficas mapeadas.
          </p>
        </div>
      )}
    </div>
  );
};
