import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentShield",
  description: "Secure AI Agent Runtime",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
