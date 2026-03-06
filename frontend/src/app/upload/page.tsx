"use client";

import { useState, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import { uploadFile } from "@/lib/api";

function UploadContent() {
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState<{ id: number; filename: string } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const ALLOWED = [".csv", ".json", ".sql", ".pdf", ".docx", ".doc"];

  const validateFile = (f: File): boolean => {
    const ext = "." + f.name.split(".").pop()?.toLowerCase();
    if (!ALLOWED.includes(ext)) {
      setError(`Unsupported: ${ext}. Allowed: ${ALLOWED.join(", ")}`);
      return false;
    }
    return true;
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped && validateFile(dropped)) {
      setFile(dropped);
      setError("");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected && validateFile(selected)) {
      setFile(selected);
      setError("");
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError("");

    try {
      const data = await uploadFile(file);
      setSuccess({ id: data.id, filename: data.original_filename });
      setFile(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  };

  return (
    <div className="page-container" style={{ maxWidth: 700 }}>
      <div className="page-header">
        <h1 className="page-title">Upload File</h1>
        <p className="page-subtitle">
          Upload a file containing PII for detection and masking.
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

      {success && (
        <div
          className="glass-card animate-fadeIn"
          style={{
            padding: 32,
            textAlign: "center",
            marginBottom: 24,
          }}
        >
          <div style={{ fontSize: "2.5rem", marginBottom: 12 }}>✅</div>
          <h3
            style={{
              fontSize: "1.2rem",
              fontWeight: 700,
              color: "var(--text-primary)",
              marginBottom: 8,
            }}
          >
            Upload Successful!
          </h3>
          <p style={{ color: "var(--text-muted)", marginBottom: 20 }}>
            <strong>{success.filename}</strong> has been uploaded.
          </p>
          <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
            <button
              className="btn-primary"
              onClick={() => router.push(`/files/${success.id}`)}
            >
              Process File →
            </button>
            <button
              className="btn-secondary"
              onClick={() => setSuccess(null)}
            >
              Upload Another
            </button>
          </div>
        </div>
      )}

      {!success && (
        <>
          <div
            className={`upload-zone ${dragOver ? "drag-over" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              accept={ALLOWED.join(",")}
              onChange={handleSelect}
              style={{ display: "none" }}
            />
            <div style={{ fontSize: "3rem", marginBottom: 16 }}>
              {dragOver ? "📥" : "📤"}
            </div>
            <h3
              style={{
                fontSize: "1.1rem",
                fontWeight: 700,
                color: "var(--text-primary)",
                marginBottom: 8,
              }}
            >
              {dragOver ? "Drop file here" : "Drag & drop file here"}
            </h3>
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", marginBottom: 16 }}>
              or click to browse
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, justifyContent: "center" }}>
              {ALLOWED.map((ext) => (
                <span key={ext} className="badge badge-neutral">
                  {ext}
                </span>
              ))}
            </div>
          </div>

          {file && (
            <div
              className="glass-card animate-fadeIn"
              style={{
                marginTop: 20,
                padding: 20,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: 10,
                    background: "rgba(99,102,241,0.1)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: "1.2rem",
                  }}
                >
                  📄
                </div>
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      fontSize: "0.95rem",
                    }}
                  >
                    {file.name}
                  </div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>
                    {formatSize(file.size)}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <button
                  className="btn-secondary"
                  onClick={() => setFile(null)}
                  style={{ padding: "8px 16px", fontSize: "0.85rem" }}
                >
                  Remove
                </button>
                <button
                  className="btn-primary"
                  onClick={handleUpload}
                  disabled={uploading}
                  style={{ padding: "8px 20px", fontSize: "0.85rem" }}
                >
                  {uploading ? (
                    <>
                      <div className="loader" style={{ width: 16, height: 16, borderWidth: 2 }} />
                      Uploading...
                    </>
                  ) : (
                    "Upload"
                  )}
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default function UploadPage() {
  return (
    <ProtectedRoute adminOnly>
      <Navbar />
      <UploadContent />
    </ProtectedRoute>
  );
}
