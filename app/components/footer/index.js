// src/app/components/Footer.js
"use client";

import LiveChatClient from "../LiveChatClient";

export default function Footer() {
  return (
   <>
    <footer className="bg-black py-4">
      <div className="mx-auto max-w-6xl px-4 text-center">
        <p className="text-white text-sm">
          Copyright © {new Date().getFullYear()} by Official Printer Support
        </p>
      </div>
    </footer>
      <LiveChatClient />
   </>
  );
}
