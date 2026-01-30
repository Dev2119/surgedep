"use client";

import React from "react";

export default function SupportGrid() {
  return (
    <div className="bg-gray-100 flex items-center justify-center px-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-5xl w-full">
        {/* Software & Driver Downloads */}
        <div className="bg-white p-8 rounded-lg shadow hover:shadow-lg transition">
          <h2 className="text-xl font-semibold mb-2">Software & Driver Downloads</h2>
          <p className="text-gray-600 mb-4">Find the right drivers for your machine</p>
          <button className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition">
            Search Driver Downloads
          </button>
        </div>

        {/* Locate Service Center */}
        <div className="bg-white p-8 rounded-lg shadow hover:shadow-lg transition">
          <h2 className="text-xl font-semibold mb-2">Locate a Service Center for Repair</h2>
          <p className="text-gray-600 mb-4">
            Search Brother's network of authorized service centers for both in and out of warranty repair.
          </p>
          <button className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition flex items-center justify-center gap-2">
            Search Service Centers <span className="text-xl">+</span>
          </button>
        </div>

        {/* Product Registration */}
        <div className="bg-white p-8 rounded-lg shadow hover:shadow-lg transition">
          <h3 className="text-lg font-semibold mb-2">Product Registration</h3>
          <p className="text-gray-600 mb-2">
            Register your Brother product for free product updates and support, news about special offers, and new product announcements.
          </p>
          <a href="#" className="text-blue-600 hover:underline">Register your product today →</a>
        </div>

        {/* Other Support Links */}
        <div className="bg-white p-8 rounded-lg shadow hover:shadow-lg transition">
          <h3 className="text-lg font-semibold mb-2">Other Support Links</h3>
          <ul className="text-blue-600 space-y-1">
            <li><a href="#" className="hover:underline">Check Warranty Status →</a></li>
            <li><a href="#" className="hover:underline">How to Find Your Serial Number →</a></li>
            <li><a href="#" className="hover:underline">Toner & Ink Recycling →</a></li>
            <li><a href="#" className="hover:underline">Product Recycling by State →</a></li>
            <li><a href="#" className="hover:underline">Purchase Extended Warranty →</a></li>
            <li><a href="#" className="hover:underline">Product Safety Data Sheets →</a></li>
          </ul>
        </div>
      </div>
    </div>
  );
}
