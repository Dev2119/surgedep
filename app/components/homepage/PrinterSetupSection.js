// src/app/components/PrinterSetupSection.js
"use client";

import Link from "next/link";
import Image from "next/image";

export default function PrinterSetupSection() {
  return (
    <section className="bg-gray-100">
      <div className="mx-auto max-w-6xl px-4 py-10 md:py-14">
        <div className="grid items-center gap-10 md:grid-cols-2">
          {/* Left: Text + CTA */}
          <div>
            <h2 className="text-3xl md:text-4xl font-extrabold text-gray-800">
              How to Setup Your Printer
            </h2>

            <p className="mt-4 text-gray-600 leading-relaxed max-w-prose">
              Click Printer Setup for step by step guidance on how to setup, configure and register
              your printer.
            </p>

            <div className="mt-6">
              <Link
                href="/driver-setup"
                className="inline-flex w-full md:w-auto items-center justify-center rounded-full bg-blue-600 px-8 py-4 text-base md:text-lg font-semibold uppercase tracking-wide text-white transition hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-300"
              >
                Run Printer Setup
              </Link>
            </div>

            <p className="mt-4 text-gray-600">
              For Assistance Please{" "}
              <Link href="/contact-us" className="text-blue-700 underline hover:no-underline">
                Contact Us
              </Link>
            </p>
          </div>

          {/* Right: Image */}
          <div className="relative h-56 sm:h-72 md:h-[320px] lg:h-[360px] rounded-lg overflow-hidden">
            <Image
              src="/images/printer-setup.png"
              alt="Printers with blue schematic background"
              fill
              priority
              className="object-cover object-center"
            />
          </div>
        </div>
      </div>
    </section>
  );
}
