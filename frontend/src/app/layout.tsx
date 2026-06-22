import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Vnotice",
  description: "Monitor CVEs and security updates",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <div className="cyber-mesh" />
        <div className="cyber-grid" />
        <div className="relative z-10">{children}</div>
      </body>
    </html>
  );
}
