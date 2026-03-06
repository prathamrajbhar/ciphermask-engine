"use client";

import Link from "next/link";
import { useAuth } from "@/lib/auth";
import { useRouter, usePathname } from "next/navigation";

export default function Navbar() {
  const { user, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  const isActive = (path: string) => pathname === path;

  if (!user) return null;

  return (
    <nav
      style={{
        position: "sticky",
        top: 0,
        zIndex: 100,
        background: "rgba(10, 14, 26, 0.85)",
        backdropFilter: "blur(20px)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div
        style={{
          maxWidth: 1280,
          margin: "0 auto",
          padding: "0 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          height: 64,
        }}
      >
        {/* Logo */}
        <Link
          href="/dashboard"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            textDecoration: "none",
          }}
        >
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: "var(--accent-gradient)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              fontSize: "1.1rem",
              color: "white",
            }}
          >
            P
          </div>
          <span
            style={{
              fontWeight: 700,
              fontSize: "1.15rem",
              background: "var(--accent-gradient)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}
          >
            CipherMask
          </span>
        </Link>

        {/* Nav Links */}
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          {[
            { href: "/dashboard", label: "Dashboard" },
            ...(user.role === "admin"
              ? [
                  { href: "/upload", label: "Upload" },
                  { href: "/audit", label: "Audit Logs" },
                ]
              : []),
          ].map((link) => (
            <Link
              key={link.href}
              href={link.href}
              style={{
                padding: "8px 16px",
                borderRadius: 8,
                fontSize: "0.9rem",
                fontWeight: 500,
                textDecoration: "none",
                color: isActive(link.href)
                  ? "var(--accent-primary-light)"
                  : "var(--text-secondary)",
                background: isActive(link.href)
                  ? "rgba(99, 102, 241, 0.1)"
                  : "transparent",
                transition: "all 0.2s",
              }}
            >
              {link.label}
            </Link>
          ))}
        </div>

        {/* User Info */}
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ textAlign: "right" }}>
            <div
              style={{
                fontSize: "0.85rem",
                fontWeight: 600,
                color: "var(--text-primary)",
              }}
            >
              {user.name}
            </div>
            <div
              style={{
                fontSize: "0.7rem",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                color:
                  user.role === "admin"
                    ? "var(--accent-primary-light)"
                    : "var(--text-muted)",
                fontWeight: 600,
              }}
            >
              {user.role}
            </div>
          </div>
          <button
            onClick={handleLogout}
            style={{
              padding: "8px 16px",
              borderRadius: 8,
              fontSize: "0.85rem",
              fontWeight: 600,
              background: "rgba(239, 68, 68, 0.1)",
              color: "var(--danger)",
              border: "1px solid rgba(239, 68, 68, 0.2)",
              cursor: "pointer",
              transition: "all 0.2s",
            }}
          >
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
}
