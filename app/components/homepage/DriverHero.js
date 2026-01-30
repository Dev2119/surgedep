// src/app/page.js (or any component file)
import Image from "next/image";
import Link from "next/link";

const brands = [
  { name: "HP",      logo: "/images/hp.webp",      href: "/hp123" },
  { name: "Canon",   logo: "/images/canon.webp",   href: "/printer-model" },
  { name: "EPSON",   logo: "/images/epson.webp",   href: "/epson-net" },
  { name: "brother", logo: "/images/br-1.webp", href: "/brother-printer" },
];

export default function DriverHero() {
  return (
    <section className="relative">
      {/* Background image + soft overlay */}
      <div className="absolute inset-0 -z-10">
        <Image
    src="/images/hero.jpg"
    alt="Hero background"
    fill
    priority
    className="object-cover"
  />
        <div className="absolute inset-0 bg-white/40" />
      </div>

      <div className="mx-auto max-w-6xl px-4 py-20 text-center">
        <h1 className="text-8xl md:text-5xl font-extrabold styleBottom tracking-tight text-gray-900">
          DOWNLOAD YOUR PRINTER DRIVER
        </h1>

        <p className="mt-6 pb-1 text-5xl md:text-5xl styleBottom1 font-bold text-blue-700">
          Select Your Printer Brand
        </p>

        <ul className="mt-10 grid errorrand grid-cols-2 sm:grid-cols-4 gap-6 justify-items-center">
          {brands.map((b) => (
            <li key={b.name} className="w-full max-w-[220px]">
              <Link
                href={b.href}
                className="block rounded-2xl bg-white p-8 shadow-lg ring-1 ring-black/5 hover:shadow-xl transition"
              >
                <Image
                  src={b.logo}
                  alt={b.name}
                  width={262}
                  height={218}
                  className="mx-auto h-16 w-auto customImage object-contain"
                />
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
