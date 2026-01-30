// src/app/components/SupportCopySection.js
"use client";

export default function SupportCopySection() {
  return (
    <section className="bg-white">
      <div className="mx-auto max-w-6xl px-6 md:px-8 py-12 md:py-16">
        <div className="grid gap-12 md:grid-cols-2 md:gap-16">
          {/* Left column */}
          <article>
            <h2 className="text-3xl md:text-4xl font-extrabold text-gray-800">
              Printer Support Customer Care
            </h2>
            <div className="mt-6 space-y-4 text-gray-700 leading-7 max-w-prose">
              <p>
                Printer Solutions offers comprehensive solutions that look at the
                problems from the root. That is why we are reputed as the best
                printer support help that you can find. We understand that
                problems bedeviling your printer may emanate from a lot of places…
              </p>
              <p>
                Printer Solutions is a team of techies who possess high level
                training in hardware and software. The team was constituted with
                the clear intention of bringing convenience and value to users…
              </p>
              <p>
                …through the provision of a customer service number available
                24 hours a day 7 days a week. We are always there when you need us.
              </p>
            </div>
          </article>

          {/* Right column */}
          <article>
            <h2 className="text-3xl md:text-4xl font-extrabold text-gray-800">
              Printer Troubleshooting
            </h2>
            <div className="mt-6 space-y-4 text-gray-700 leading-7 max-w-prose">
              <p>
                Printers are the most widely used all across the globe and provide
                the most advanced features in their peripherals. But with so many
                features these printers are also very sophisticated…
              </p>
              <p>
                Printer Solutions provides best-in-class Support and Service for
                Printers. Our technicians use the latest tools and techniques to
                diagnose and fix issues of all kinds of printers.
              </p>
              <p>
                We can help you install printers, scanners, and drivers, configure
                networks, and update drivers to resolve errors—quickly and reliably.
              </p>
            </div>
          </article>
        </div>
      </div>
    </section>
  );
}
