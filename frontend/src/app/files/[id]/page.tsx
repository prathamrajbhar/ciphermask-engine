"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import { listFiles, maskFile, getReport, downloadSanitized } from "@/lib/api";
import { useAuth } from "@/lib/auth";

interface FileItem {
  id: number;
  original_filename: string;
  file_type: string;
  status: string;
  uploaded_by: number;
  sanitized_path?: string;
  created_at: string;
}

interface Report {
  id: number;
  file_id: number;
  total_pii_found: number;
  pii_breakdown: Record<string, number>;
  risk_score: number;
  compliance_status: string;
  created_at: string;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    uploaded: { cls: "badge-info", label: "Uploaded" },
    processing: { cls: "badge-warning", label: "Processing" },
    completed: { cls: "badge-success", label: "Completed" },
    failed: { cls: "badge-danger", label: "Failed" },
  };
  const s = map[status] || { cls: "badge-neutral", label: status };
  return <span className={`badge ${s.cls}`}>{s.label}</span>;
}

function RiskBadge({ score }: { score: number }) {
  if (score > 9) return <span className="badge badge-danger">Critical ({score.toFixed(1)})</span>;
  if (score > 7) return <span className="badge badge-danger">High Risk ({score.toFixed(1)})</span>;
  if (score > 4) return <span className="badge badge-warning">Medium Risk ({score.toFixed(1)})</span>;
  if (score > 0) return <span className="badge badge-info">Low Risk ({score.toFixed(1)})</span>;
  return <span className="badge badge-success">No Risk</span>;
}

function FileDetailContent({ fileId }: { fileId: number }) {
  const { user } = useAuth();
  const [file, setFile] = useState<FileItem | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [masking, setMasking] = useState(false);
  const [maskResult, setMaskResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  const fetchData = async () => {
    try {
      const filesResp = await listFiles();
      const found = filesResp.files?.find((f: FileItem) => f.id === fileId);
      if (found) {
        setFile(found);
        if (found.status === "completed") {
          try {
            const r = await getReport(fileId);
            setReport(r);
          } catch {
            // report might not exist yet
          }
        }
      }
    } catch {
      setError("Failed to load file data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId]);

  const handleMask = async () => {
    setMasking(true);
    setError("");
    try {
      const result = await maskFile(fileId);
      setMaskResult(result);
      // Refresh data
      await fetchData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Masking failed");
    } finally {
      setMasking(false);
    }
  };

  const handleDownload = async () => {
    try {
      const res = await downloadSanitized(fileId);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sanitized_${file?.original_filename || "file"}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Download failed");
    }
  };

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: 80 }}>
        <div className="loader" />
      </div>
    );
  }

  if (!file) {
    return (
      <div className="page-container" style={{ textAlign: "center", padding: 80 }}>
        <h2 style={{ color: "var(--text-primary)" }}>File not found</h2>
        <Link href="/dashboard" className="btn-primary" style={{ marginTop: 20, textDecoration: "none", display: "inline-flex" }}>
          ← Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="page-container" style={{ maxWidth: 900 }}>
      <div className="page-header">
        <Link
          href="/dashboard"
          style={{
            color: "var(--text-muted)",
            textDecoration: "none",
            fontSize: "0.85rem",
            fontWeight: 600,
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            marginBottom: 12,
          }}
        >
          ← Back to Dashboard
        </Link>
        <h1 className="page-title">{file.original_filename}</h1>
        <p className="page-subtitle">
          Uploaded{" "}
          {new Date(file.created_at).toLocaleDateString("en-IN", {
            day: "2-digit",
            month: "long",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}
        </p>
      </div>

      {error && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: 8,
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.3)",
            color: "var(--danger)",
            fontSize: "0.85rem",
            marginBottom: 20,
          }}
        >
          {error}
        </div>
      )}

      {/* File Info Card */}
      <div
        className="glass-card animate-fadeIn"
        style={{
          padding: 28,
          marginBottom: 24,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: 24,
        }}
      >
        <div>
          <div style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
            File Type
          </div>
          <span className="badge badge-neutral">.{file.file_type}</span>
        </div>
        <div>
          <div style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
            Status
          </div>
          <StatusBadge status={file.status} />
        </div>
        <div>
          <div style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
            File ID
          </div>
          <span style={{ fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
            #{file.id}
          </span>
        </div>
      </div>

      {/* Actions */}
      <div
        className="glass-card animate-fadeIn"
        style={{
          padding: 28,
          marginBottom: 24,
          animationDelay: "100ms",
        }}
      >
        <h3
          style={{
            fontSize: "1rem",
            fontWeight: 700,
            color: "var(--text-primary)",
            marginBottom: 16,
          }}
        >
          Actions
        </h3>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
          {file.status === "uploaded" && user?.role === "admin" && (
            <button
              className="btn-primary"
              onClick={handleMask}
              disabled={masking}
            >
              {masking ? (
                <>
                  <div className="loader" style={{ width: 16, height: 16, borderWidth: 2 }} />
                  Running PII Detection...
                </>
              ) : (
                "🔒 Run Masking Pipeline"
              )}
            </button>
          )}

          {file.status === "completed" && (
            <>
              <button className="btn-primary" onClick={handleDownload}>
                ⬇ Download Sanitized File
              </button>
              {user?.role === "admin" && (
                <Link
                  href={`/vault/${file.id}`}
                  className="btn-secondary"
                  style={{ textDecoration: "none" }}
                >
                  🔑 Token Vault
                </Link>
              )}
            </>
          )}

          {file.status === "processing" && (
            <div style={{ display: "flex", alignItems: "center", gap: 12, color: "var(--warning)" }}>
              <div className="loader" style={{ width: 20, height: 20, borderWidth: 2, borderTopColor: "var(--warning)" }} />
              <span style={{ fontWeight: 600 }}>Processing in progress...</span>
            </div>
          )}

          {file.status === "failed" && user?.role === "admin" && (
            <button className="btn-danger" onClick={handleMask} disabled={masking}>
              🔄 Retry Masking
            </button>
          )}
        </div>
      </div>

      {/* Mask Result (immediate feedback) */}
      {maskResult && (
        <div
          className="glass-card animate-fadeIn"
          style={{
            padding: 28,
            marginBottom: 24,
            borderColor: "rgba(16, 185, 129, 0.3)",
          }}
        >
          <h3
            style={{
              fontSize: "1rem",
              fontWeight: 700,
              color: "var(--success)",
              marginBottom: 16,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            ✅ Masking Complete
          </h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: 16,
            }}
          >
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", marginBottom: 4 }}>
                PII Found
              </div>
              <div style={{ fontSize: "1.5rem", fontWeight: 800, color: "var(--text-primary)" }}>
                {maskResult.total_pii_found as number}
              </div>
            </div>
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", marginBottom: 4 }}>
                Risk Score
              </div>
              <RiskBadge score={maskResult.risk_score as number} />
            </div>
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", marginBottom: 4 }}>
                Status
              </div>
              <span className="badge badge-success">
                {(maskResult.compliance_status as string)?.replace(/_/g, " ")}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Compliance Report */}
      {report && (
        <div
          className="glass-card animate-fadeIn"
          style={{
            padding: 28,
            animationDelay: "200ms",
          }}
        >
          <h3
            style={{
              fontSize: "1rem",
              fontWeight: 700,
              color: "var(--text-primary)",
              marginBottom: 20,
            }}
          >
            📊 Compliance Report
          </h3>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 20,
              marginBottom: 24,
            }}
          >
            <div
              style={{
                padding: 16,
                borderRadius: 10,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
              }}
            >
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", marginBottom: 6 }}>
                Total PII Found
              </div>
              <div style={{ fontSize: "1.8rem", fontWeight: 800, color: "var(--text-primary)" }}>
                {report.total_pii_found}
              </div>
            </div>
            <div
              style={{
                padding: 16,
                borderRadius: 10,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
              }}
            >
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", marginBottom: 6 }}>
                Risk Score
              </div>
              <RiskBadge score={report.risk_score} />
            </div>
            <div
              style={{
                padding: 16,
                borderRadius: 10,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
              }}
            >
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", marginBottom: 6 }}>
                Compliance Status
              </div>
              <span
                className={`badge ${
                  report.compliance_status === "compliant"
                    ? "badge-success"
                    : report.compliance_status === "critical" || report.compliance_status === "high_risk"
                    ? "badge-danger"
                    : report.compliance_status === "medium_risk"
                    ? "badge-warning"
                    : "badge-info"
                }`}
              >
                {report.compliance_status.replace(/_/g, " ")}
              </span>
            </div>
          </div>

          {/* PII Breakdown */}
          {report.pii_breakdown && Object.keys(report.pii_breakdown).length > 0 && (
            <div>
              <h4
                style={{
                  fontSize: "0.85rem",
                  fontWeight: 700,
                  color: "var(--text-secondary)",
                  marginBottom: 12,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                PII Breakdown
              </h4>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                {Object.entries(report.pii_breakdown).map(([type, count]) => (
                  <div
                    key={type}
                    style={{
                      padding: "10px 16px",
                      borderRadius: 10,
                      background: "var(--bg-secondary)",
                      border: "1px solid var(--border)",
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.8rem",
                        fontWeight: 600,
                        color: "var(--text-secondary)",
                      }}
                    >
                      {type.replace(/_/g, " ")}
                    </span>
                    <span
                      style={{
                        background: "var(--accent-gradient)",
                        color: "white",
                        padding: "2px 8px",
                        borderRadius: 6,
                        fontSize: "0.75rem",
                        fontWeight: 700,
                      }}
                    >
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function FileDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <ProtectedRoute>
      <Navbar />
      <FileDetailContent fileId={parseInt(id)} />
    </ProtectedRoute>
  );
}
