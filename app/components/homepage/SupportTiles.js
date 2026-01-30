"use client";

import Link from "next/link";

const tiles = [
  { title: "Software and Drivers", href: "/contact-us", bg: "bg-indigo-500" },
  { title: "Solution Center", href: "/contact-us", bg: "bg-indigo-500"
    // image: "/images/solution.jpg" 

  },
  { title: "Diagnostic Tools to fix issue", href: "/contact-us",bg: "bg-indigo-500" },
];

export default function SupportTiles() {
  return (
    <section className="mx-auto max-w-6xl px-4 py-8">
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        {tiles.map((t) => (
          <Link
            key={t.title}
            href={t.href}
            className="group relative block h-64 rounded-xl overflow-hidden shadow ring-1 ring-black/5"
          >
            {t.image ? (
              <>
                <div
                  className="absolute inset-0 bg-center bg-cover transition-transform duration-500 group-hover:scale-105"
                  style={{ backgroundImage: `url('${t.image}')` }}
                />
                <div className="absolute inset-0 bg-black/40 group-hover:bg-black/45 transition-colors" />
              </>
            ) : (
              <div className={`absolute inset-0 ${t.bg ?? "bg-gray-200"}`} />
            )}

            <div className="relative z-10 flex h-full flex-col items-center justify-center text-white">
              <h3 className="px-4 text-center text-lg md:text-xl font-medium">
                {t.title}
              </h3>
              <span className="mt-6 inline-flex h-14 w-14 items-center justify-center rounded-full border border-white/80 transition group-hover:scale-105">
                <svg
                  width="28"
                  height="28"
                  viewBox="0 0 24 24"
                  fill="none"
                  className="translate-x-0 transition-transform duration-300 group-hover:translate-x-0.5"
                >
                  <path d="M9 6l6 6-6 6" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
