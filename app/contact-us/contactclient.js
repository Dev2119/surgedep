

"use client";

import { useState } from "react";
import Footer from "../components/footer";
import Header from "../components/header";

export default function Contactpage() {
  const [fullName, setFullName] = useState("");
  const [modelNumber, setModelNumber] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState(null); 

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus(null);

    try {
      const res = await fetch("/api/contactmail", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fullName,
          modelNumber,
          phoneNumber,
          description,
        }),
      });

      const data = await res.json();

      if (res.ok && data?.success) {
        setStatus("success");
        setFullName("");
        setModelNumber("");
        setPhoneNumber("");
        setDescription("");
      } else {
        setStatus("error");
      }
    } catch (err) {
      console.error(err);
      setStatus("error");
    }
  };

  return (
    <>
       <Header />
    <div className="min-h-screen bg-gray-100 flex flex-col items-center py-10">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-6 rounded-2xl shadow-lg w-[95%] max-w-5xl"
      >
        <div className="grid gap-4 md:grid-cols-3">
          <div className="flex flex-col">
            <label className="font-medium text-gray-700">
              Full Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              name="fullName"
              placeholder="Full Name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
              className="border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>

          <div className="flex flex-col">
            <label className="font-medium text-gray-700">
              Model Number <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              name="modelNumber"
              placeholder="Model Number"
              value={modelNumber}
              onChange={(e) => setModelNumber(e.target.value)}
              required
              className="border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>

          <div className="flex flex-col">
            <label className="font-medium text-gray-700">
              Phone Number <span className="text-red-500">*</span>
            </label>
            <input
              type="tel"
              name="phoneNumber"
              placeholder="Phone Number"
              value={phoneNumber}
              onChange={(e) => setPhoneNumber(e.target.value)}
              required
              className="border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>
        </div>

        <div className="mt-5">
          <label className="font-medium text-gray-700">Description</label>
          <textarea
            name="description"
            placeholder="Type your message..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={6}
            className="w-full border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
        </div>

        {status === "success" && (
          <p className="mt-4 text-green-600">✅ Your query has been submitted.</p>
        )}
        {status === "error" && (
          <p className="mt-4 text-red-600">❌ Something went wrong. Try again.</p>
        )}

        <div className="mt-6">
          <button
            type="submit"
            className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition"
          >
            SUBMIT A QUERY
          </button>
        </div>
      </form>
    </div>
     <Footer/>
     </>
  );
}
