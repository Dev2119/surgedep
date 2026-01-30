"use client";

import Image from "next/image";
import { useState } from "react";

export default function ContactPage() {
  const [formData, setFormData] = useState({ name: "", mnumber: "",pnumber: "", message: "" });
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);   // ✅ track success state
  const [error, setError] = useState("");          // ✅ track error message

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setSuccess(false);

    try {
      const res = await fetch("/api/epsoncontsct", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await res.json();
      if (data.success) {
        setSuccess(true);    
        setFormData({ name: "", mnumber: "",pnumber: "", message: "" }); 
      } else {
        setError("Failed to send message.");
      }
    } catch (err) {
      console.error(err);
      setError("Error sending message.");
    } finally {
      setLoading(false);
    }
  }; 

  return (
    <main className="min-h-screen bg-[#f5f7fb] py-8">
      {/* Return to top bar */}
      <div className="mx-auto max-w-4xl px-4">
        <details className="group mb-4 w-fit cursor-pointer select-none text-sm font-semibold text-gray-900">
          <summary className="flex items-center gap-2 list-none">
            <span className="inline-block rounded-sm border border-gray-300 bg-white p-1">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="h-4 w-4 transition-transform group-open:-rotate-90">
                <path d="M8 10l4-4 4 4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            Return To Top
          </summary>
        </details>
      </div>

      {/* Top card: Installing + error preview image */}
      <section className="mx-auto max-w-4xl px-4">
        <div className="">
         <Image
                                    src="/images/epson-error.jpg"
                                     alt="HP"
                                    width={837}
                                     height={598}
                                    priority
                                       className="object-contain"
                                  />
        </div>
      </section>

      {/* Form card */}
      <section className="mx-auto mt-8 max-w-4xl px-4">
        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm md:p-8">
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          name="name"
          placeholder="Your Name"
          value={formData.name}
          onChange={handleChange}
          required
          style={{ width: "100%", padding: "10px", marginBottom: "10px" }}
        />
        <input
          type="text"
          name="mnumber"
          placeholder="Model Number"
          value={formData.mnumber}
          onChange={handleChange}
          required
          style={{ width: "100%", padding: "10px", marginBottom: "10px" }}
        />
        <input
          type="text"
          name="pnumber"
          placeholder="Phone Number "
          value={formData.pnumber}
          onChange={handleChange}
          required
          style={{ width: "100%", padding: "10px", marginBottom: "10px" }}
        />
        <textarea
          name="message"
          placeholder="Type Your Message"
          value={formData.message}
          onChange={handleChange}
          required
          style={{ width: "100%", padding: "10px", marginBottom: "10px", minHeight: "120px" }}
        />
        <button type="submit" disabled={loading} style={{ padding: "10px 20px" }}>
          {loading ? "Sending..." : "Send"}
        </button>
      </form>
       {/* ✅ Success / Error messages */}
      {success && <p style={{ color: "green", marginTop: "15px" }}>✅ Your message was sent successfully!</p>}
      {error && <p style={{ color: "red", marginTop: "15px" }}>{error}</p>}
        </div>
      </section>
    </main>
  );
}
