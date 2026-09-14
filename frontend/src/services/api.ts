import {
  AnalysisOptions,
  EmailAnalysisRequest,
  EmailAnalysisResponse,
  SampleId,
} from '../types/email';

const API_BASE_URL = '';

export class ApiError extends Error {
  status: number;
  data?: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

/**
 * Sends raw email header to backend for forensic analysis.
 */
export async function analyzeEmail(
  rawHeader: string,
  options: AnalysisOptions = { live_dns: true, rdap_lookup: true, rbl_check: true }
): Promise<EmailAnalysisResponse> {
  const payload: EmailAnalysisRequest = {
    raw_header: rawHeader,
    options,
  };

  const response = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let errorMessage = `Erro HTTP ${response.status}: Falha ao analisar cabeçalho`;
    try {
      const errorJson = await response.json();
      if (errorJson.detail) {
        errorMessage = typeof errorJson.detail === 'string'
          ? errorJson.detail
          : JSON.stringify(errorJson.detail);
      }
    } catch {
      // Ignore JSON parse failure
    }
    throw new ApiError(errorMessage, response.status);
  }

  return response.json();
}

/**
 * Fetches pre-configured sample email headers by ID.
 */
export async function fetchSample(
  sampleId: SampleId | string
): Promise<{ sample_id: string; raw_header: string }> {
  const response = await fetch(`${API_BASE_URL}/api/samples/${sampleId}`);

  if (!response.ok) {
    let errorMessage = `Amostra '${sampleId}' não encontrada`;
    try {
      const errorJson = await response.json();
      if (errorJson.detail) {
        errorMessage = typeof errorJson.detail === 'string'
          ? errorJson.detail
          : JSON.stringify(errorJson.detail);
      }
    } catch {
      // Ignore
    }
    throw new ApiError(errorMessage, response.status);
  }

  return response.json();
}

/**
 * Requests PDF report generation from backend and returns the binary blob.
 */
export async function exportPdf(
  rawHeader: string,
  options: AnalysisOptions = { live_dns: true, rdap_lookup: true, rbl_check: true }
): Promise<Blob> {
  const payload: EmailAnalysisRequest = {
    raw_header: rawHeader,
    options,
  };

  const response = await fetch(`${API_BASE_URL}/api/export-pdf`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let errorMessage = `Erro HTTP ${response.status}: Falha ao gerar PDF`;
    try {
      const errorJson = await response.json();
      if (errorJson.detail) {
        errorMessage = typeof errorJson.detail === 'string'
          ? errorJson.detail
          : JSON.stringify(errorJson.detail);
      }
    } catch {
      // Ignore
    }
    throw new ApiError(errorMessage, response.status);
  }

  return response.blob();
}

/**
 * Helper to trigger browser download of a Blob.
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}
