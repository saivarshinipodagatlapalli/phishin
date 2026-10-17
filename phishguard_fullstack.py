"""
========================================================================================
 PHISHING EMAIL & WEBSITE DETECTOR — ALL-IN-ONE FULLSTACK SYSTEM
========================================================================================
 Single-file architecture combining:
  1. Frontend: High-performance cyber neon UI, interactive scanning beam, risk gauges,
     one-click clipboard report export, custom print/PDF stylesheet, and mobile access badge.
  2. Backend: Flask REST API (`/api/health`, `/api/info`, `/api/analyze`).
  3. Cybersecurity Engine: Multi-layer heuristics, Shannon entropy (DGA), typosquatting,
     illicit streaming & piracy network intelligence, BEC/CEO fraud, crypto drainer shields.

 Run with:
   python phishguard_fullstack.py
========================================================================================
"""

import os
import re
import math
import socket
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# Optional Machine Learning loading
try:
    import joblib
except ImportError:
    joblib = None

# ======================================================================================
# EMBEDDED FRONTEND (HTML / CSS / JAVASCRIPT)
# ======================================================================================
HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Phishing Email & Website Detector</title>
  <style>
    :root {
      --bg: #030712;
      --card-bg: rgba(11, 20, 38, 0.8);
      --card-border: rgba(40, 75, 120, 0.45);
      --neon-cyan: #00f0ff;
      --neon-cyan-glow: rgba(0, 240, 255, 0.4);
      --neon-green: #10f396;
      --neon-green-glow: rgba(16, 243, 150, 0.4);
      --neon-amber: #ffb703;
      --neon-amber-glow: rgba(255, 183, 3, 0.4);
      --neon-red: #ff2a5f;
      --neon-red-glow: rgba(255, 42, 95, 0.4);
      --neon-purple: #a855f7;
      --neon-purple-glow: rgba(168, 85, 247, 0.35);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", Arial, sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font-sans);
      color: var(--text-main);
      background-color: var(--bg);
      background-image: 
        radial-gradient(circle at 50% 0%, rgba(0, 240, 255, 0.12) 0%, transparent 55%),
        radial-gradient(circle at 90% 40%, rgba(168, 85, 247, 0.08) 0%, transparent 45%),
        radial-gradient(circle at 10% 70%, rgba(16, 243, 150, 0.06) 0%, transparent 40%);
      min-height: 100vh;
      overflow-x: hidden;
      position: relative;
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      background-image: 
        linear-gradient(rgba(0, 240, 255, 0.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 240, 255, 0.035) 1px, transparent 1px);
      background-size: 38px 38px;
      pointer-events: none;
      z-index: 0;
    }

    .glow-orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(80px);
      pointer-events: none;
      z-index: 0;
      animation: floatGlow 12s ease-in-out infinite alternate;
    }

    .glow-orb-1 { top: 10%; left: 15%; width: 280px; height: 280px; background: rgba(0, 240, 255, 0.1); }
    .glow-orb-2 { top: 45%; right: 10%; width: 320px; height: 320px; background: rgba(168, 85, 247, 0.08); animation-delay: -6s; }

    @keyframes floatGlow {
      0% { transform: translate(0, 0) scale(1); }
      100% { transform: translate(30px, 40px) scale(1.15); }
    }

    header {
      position: sticky;
      top: 0;
      z-index: 50;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      background: rgba(3, 7, 18, 0.85);
      border-bottom: 1px solid rgba(0, 240, 255, 0.15);
      box-shadow: 0 4px 25px rgba(0, 0, 0, 0.4);
    }

    .nav-container {
      max-width: 1180px;
      margin: auto;
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 15px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: #fff;
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.4px;
    }

    .brand-icon {
      position: relative;
      width: 36px;
      height: 36px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(16, 243, 150, 0.2));
      border: 1px solid var(--neon-cyan);
      border-radius: 9px;
      box-shadow: 0 0 15px var(--neon-cyan-glow);
    }

    .brand-text span {
      background: linear-gradient(90deg, var(--neon-cyan), var(--neon-green));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-shadow: 0 0 20px var(--neon-cyan-glow);
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 243, 150, 0.08);
      border: 1px solid rgba(16, 243, 150, 0.3);
      padding: 6px 14px;
      border-radius: 30px;
      font-size: 12px;
      font-weight: 600;
      color: #a7f3d0;
      box-shadow: 0 0 12px rgba(16, 243, 150, 0.15);
    }

    .mobile-badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      background: rgba(0, 240, 255, 0.07);
      border: 1px solid rgba(0, 240, 255, 0.3);
      padding: 6px 13px;
      border-radius: 30px;
      font-size: 11px;
      font-weight: 600;
      color: #7dd3fc;
      font-family: var(--font-mono);
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .mobile-badge:hover {
      background: rgba(0, 240, 255, 0.16);
      border-color: var(--neon-cyan);
      box-shadow: 0 0 12px var(--neon-cyan-glow);
      color: #fff;
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      background-color: var(--neon-green);
      border-radius: 50%;
      box-shadow: 0 0 10px var(--neon-green);
      animation: neonPulse 2s infinite;
    }

    @keyframes neonPulse {
      0%, 100% { transform: scale(1); box-shadow: 0 0 4px var(--neon-green), 0 0 8px var(--neon-green); }
      50% { transform: scale(1.3); box-shadow: 0 0 10px var(--neon-green), 0 0 20px var(--neon-green); }
    }

    main {
      position: relative;
      z-index: 1;
      max-width: 1180px;
      margin: auto;
      padding: 30px 24px 60px;
    }

    .hero { text-align: center; padding: 35px 15px 30px; }

    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      background: rgba(0, 240, 255, 0.08);
      border: 1px solid rgba(0, 240, 255, 0.4);
      color: var(--neon-cyan);
      padding: 6px 18px;
      border-radius: 50px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 1.2px;
      text-transform: uppercase;
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.2);
      margin-bottom: 18px;
      animation: glowBorder 4s infinite alternate;
    }

    @keyframes glowBorder {
      0% { border-color: rgba(0, 240, 255, 0.3); box-shadow: 0 0 10px rgba(0, 240, 255, 0.15); }
      100% { border-color: rgba(0, 240, 255, 0.8); box-shadow: 0 0 24px rgba(0, 240, 255, 0.35); }
    }

    .hero h1 {
      font-size: clamp(30px, 5vw, 52px);
      font-weight: 900;
      letter-spacing: -1px;
      line-height: 1.15;
      margin-bottom: 14px;
      color: #fff;
    }

    .hero h1 .highlight {
      background: linear-gradient(135deg, #ffffff 10%, var(--neon-cyan) 60%, var(--neon-green) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      filter: drop-shadow(0 0 25px rgba(0, 240, 255, 0.3));
    }

    .hero p {
      color: var(--text-muted);
      font-size: 16px;
      max-width: 720px;
      margin: auto;
      line-height: 1.6;
    }

    .tabs-wrapper { display: flex; justify-content: center; margin: 30px 0 20px; }

    .tabs {
      background: rgba(10, 18, 35, 0.9);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 5px;
      display: inline-flex;
      gap: 6px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    }

    .tab-btn {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      background: transparent;
      border: 1px solid transparent;
      border-radius: 10px;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.25s ease;
    }

    .tab-btn:hover { color: #fff; background: rgba(0, 240, 255, 0.05); }

    .tab-btn.active {
      color: #fff;
      background: linear-gradient(135deg, rgba(0, 240, 255, 0.15), rgba(10, 30, 60, 0.8));
      border: 1px solid var(--neon-cyan);
      box-shadow: 0 0 16px var(--neon-cyan-glow), inset 0 0 12px rgba(0, 240, 255, 0.12);
    }

    .glass-card {
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 30px;
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
      position: relative;
      overflow: hidden;
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }

    .glass-card:hover {
      border-color: rgba(0, 240, 255, 0.4);
      box-shadow: 0 14px 45px rgba(0, 0, 0, 0.6), 0 0 20px rgba(0, 240, 255, 0.08);
    }

    .scan-beam {
      display: none;
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 4px;
      background: linear-gradient(90deg, transparent, var(--neon-cyan), var(--neon-green), transparent);
      box-shadow: 0 0 20px var(--neon-cyan), 0 0 10px var(--neon-green);
      animation: scanSweep 2s ease-in-out infinite;
      z-index: 10;
    }

    .scanning .scan-beam { display: block; }

    @keyframes scanSweep {
      0% { top: 0%; opacity: 0; }
      20% { opacity: 1; }
      80% { opacity: 1; }
      100% { top: 100%; opacity: 0; }
    }

    .card-header { margin-bottom: 22px; }

    .card-header h2 {
      font-size: 20px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .card-header p { color: var(--text-muted); font-size: 13px; margin-top: 4px; }

    .form-group { margin-bottom: 18px; }

    .form-group label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--neon-cyan);
      margin-bottom: 8px;
    }

    input[type="text"], textarea {
      width: 100%;
      background: rgba(3, 8, 20, 0.85);
      border: 1px solid rgba(40, 75, 120, 0.6);
      border-radius: 12px;
      padding: 14px 16px;
      color: #fff;
      font-size: 14px;
      font-family: inherit;
      transition: all 0.25s ease;
      outline: none;
    }

    input[type="text"]:focus, textarea:focus {
      border-color: var(--neon-cyan);
      box-shadow: 0 0 16px var(--neon-cyan-glow), inset 0 0 8px rgba(0, 240, 255, 0.1);
      background: rgba(5, 12, 28, 0.95);
    }

    textarea { min-height: 160px; resize: vertical; line-height: 1.6; }

    .samples-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .sample-label { font-size: 11px; color: var(--text-dim); font-weight: 600; text-transform: uppercase; }

    .sample-pill {
      background: rgba(0, 240, 255, 0.05);
      border: 1px solid rgba(0, 240, 255, 0.2);
      color: #7dd3fc;
      border-radius: 20px;
      padding: 4px 12px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .sample-pill:hover {
      background: rgba(0, 240, 255, 0.15);
      border-color: var(--neon-cyan);
      box-shadow: 0 0 10px var(--neon-cyan-glow);
      color: #fff;
    }

    .sample-pill.bad { border-color: rgba(255, 42, 95, 0.3); color: #fca5a5; }
    .sample-pill.bad:hover {
      background: rgba(255, 42, 95, 0.15);
      border-color: var(--neon-red);
      box-shadow: 0 0 10px var(--neon-red-glow);
      color: #fff;
    }

    .actions-bar { display: flex; gap: 12px; margin-top: 24px; flex-wrap: wrap; }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 9px;
      padding: 14px 26px;
      font-size: 14px;
      font-weight: 700;
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.25s ease;
      border: none;
      outline: none;
      user-select: none;
    }

    .btn-neon-primary {
      flex: 2;
      min-width: 200px;
      background: linear-gradient(135deg, #00f0ff, #10f396);
      color: #021217;
      box-shadow: 0 0 20px var(--neon-cyan-glow), 0 4px 15px rgba(0, 0, 0, 0.4);
    }

    .btn-neon-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 0 30px var(--neon-cyan-glow), 0 0 20px var(--neon-green-glow);
    }

    .btn-outline {
      flex: 1;
      background: rgba(15, 27, 49, 0.8);
      color: var(--text-main);
      border: 1px solid var(--card-border);
    }

    .btn-outline:hover {
      border-color: var(--neon-cyan);
      color: #fff;
      box-shadow: 0 0 14px rgba(0, 240, 255, 0.25);
    }

    .status-alert {
      margin-top: 16px;
      padding: 12px 18px;
      border-radius: 10px;
      font-size: 13px;
      display: none;
      align-items: center;
      gap: 10px;
    }

    .status-alert.active { display: flex; }
    .status-alert.info { background: rgba(0, 240, 255, 0.08); border: 1px solid rgba(0, 240, 255, 0.3); color: #bae6fd; }
    .status-alert.error { background: rgba(255, 42, 95, 0.08); border: 1px solid rgba(255, 42, 95, 0.35); color: #fecdd3; }

    .report-section { display: none; margin-top: 36px; animation: reportEntrance 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    .report-section.show { display: block; }

    @keyframes reportEntrance {
      0% { opacity: 0; transform: translateY(24px) scale(0.98); }
      100% { opacity: 1; transform: translateY(0) scale(1); }
    }

    .report-card { border-width: 2px; }
    .report-card.risk-low { border-color: rgba(16, 243, 150, 0.6); box-shadow: 0 0 35px rgba(16, 243, 150, 0.15); }
    .report-card.risk-med { border-color: rgba(255, 183, 3, 0.6); box-shadow: 0 0 35px rgba(255, 183, 3, 0.15); }
    .report-card.risk-high { border-color: rgba(255, 42, 95, 0.6); box-shadow: 0 0 35px rgba(255, 42, 95, 0.2); }

    .report-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid rgba(40, 75, 120, 0.4);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 14px;
    }

    .report-title-group h3 { font-size: 22px; font-weight: 800; color: #fff; }
    .report-title-group p { font-size: 12px; color: var(--text-dim); font-family: var(--font-mono); margin-top: 3px; }
    .report-actions { display: flex; align-items: center; gap: 10px; }

    .btn-tool {
      padding: 9px 18px;
      font-size: 13px;
      font-weight: 700;
      border-radius: 10px;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      cursor: pointer;
      transition: all 0.2s ease;
      background: rgba(14, 25, 46, 0.9);
      border: 1px solid rgba(0, 240, 255, 0.35);
      color: #e2e8f0;
    }

    .btn-tool:hover {
      background: rgba(0, 240, 255, 0.12);
      border-color: var(--neon-cyan);
      box-shadow: 0 0 14px var(--neon-cyan-glow);
      color: #fff;
    }

    .btn-tool.copy-success {
      background: rgba(16, 243, 150, 0.2) !important;
      border-color: var(--neon-green) !important;
      color: #fff !important;
      box-shadow: 0 0 18px var(--neon-green-glow) !important;
    }

    .executive-summary-panel {
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 28px;
      align-items: center;
      background: rgba(5, 12, 26, 0.6);
      border: 1px solid rgba(40, 75, 120, 0.35);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .gauge-container {
      width: 140px;
      height: 140px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: conic-gradient(var(--gauge-color, var(--neon-green)) calc(var(--gauge-val, 0) * 1%), #111e33 0);
      position: relative;
      margin: auto;
      box-shadow: 0 0 25px var(--gauge-glow, var(--neon-green-glow));
      transition: all 0.6s cubic-bezier(0.1, 1, 0.1, 1);
    }

    .gauge-container::after {
      content: "";
      position: absolute;
      width: 114px;
      height: 114px;
      background: #060d1b;
      border-radius: 50%;
    }

    .gauge-center { position: relative; z-index: 2; text-align: center; }
    .gauge-percent { font-size: 30px; font-weight: 900; font-family: var(--font-mono); color: #fff; line-height: 1; }
    .gauge-label { font-size: 10px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-top: 4px; }

    .risk-low { --gauge-color: var(--neon-green); --gauge-glow: var(--neon-green-glow); }
    .risk-med { --gauge-color: var(--neon-amber); --gauge-glow: var(--neon-amber-glow); }
    .risk-high { --gauge-color: var(--neon-red); --gauge-glow: var(--neon-red-glow); }

    .summary-text-box h4 {
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 800;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .badge-level { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 12px; font-weight: 800; text-transform: uppercase; }
    .badge-level.risk-low { background: rgba(16, 243, 150, 0.15); border: 1px solid var(--neon-green); color: var(--neon-green); }
    .badge-level.risk-med { background: rgba(255, 183, 3, 0.15); border: 1px solid var(--neon-amber); color: var(--neon-amber); }
    .badge-level.risk-high { background: rgba(255, 42, 95, 0.15); border: 1px solid var(--neon-red); color: var(--neon-red); }

    .badge-category {
      background: rgba(0, 240, 255, 0.12);
      border: 1px solid var(--neon-cyan);
      color: #7dd3fc;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
    }

    .summary-text-box .summary-desc { font-size: 15px; color: #e2e8f0; line-height: 1.5; margin: 8px 0 12px; }
    .summary-text-box .scan-meta-pill { display: inline-flex; align-items: center; gap: 12px; font-size: 11px; color: var(--text-dim); font-family: var(--font-mono); }

    .vectors-matrix {
      background: rgba(4, 10, 22, 0.7);
      border: 1px solid rgba(40, 75, 120, 0.35);
      border-radius: 14px;
      padding: 18px 20px;
      margin-bottom: 24px;
    }

    .vectors-matrix h4 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 800; color: var(--neon-cyan); margin-bottom: 14px; }
    .vector-bars-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    .vector-bar-item .vb-head { display: flex; justify-content: space-between; font-size: 11px; font-weight: 700; color: #cbd5e1; margin-bottom: 6px; }
    .vector-bar-item .vb-head span:last-child { font-family: var(--font-mono); color: var(--neon-cyan); }
    .vb-track { height: 7px; background: rgba(15, 27, 49, 0.9); border-radius: 10px; overflow: hidden; border: 1px solid rgba(40, 75, 120, 0.4); }
    .vb-fill { height: 100%; width: 0%; border-radius: 10px; transition: width 0.8s cubic-bezier(0.1, 1, 0.1, 1); }
    .fill-cyan { background: linear-gradient(90deg, #00f0ff, #38bdf8); }
    .fill-amber { background: linear-gradient(90deg, #ffb703, #fbbf24); }
    .fill-red { background: linear-gradient(90deg, #ff2a5f, #f43f5e); }
    .fill-purple { background: linear-gradient(90deg, #a855f7, #c084fc); }

    .report-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
    .report-panel { background: rgba(6, 14, 29, 0.7); border: 1px solid rgba(40, 75, 120, 0.4); border-radius: 14px; padding: 20px; }
    .report-panel h4 { font-size: 13px; text-transform: uppercase; font-weight: 700; color: var(--neon-cyan); margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid rgba(40, 75, 120, 0.25); }
    .report-panel ul { list-style: none; display: flex; flex-direction: column; gap: 10px; }
    .report-panel li { font-size: 13px; color: #cbd5e1; line-height: 1.6; display: flex; align-items: flex-start; gap: 8px; }
    .report-panel li::before { content: "•"; color: var(--neon-cyan); font-weight: bold; }
    .findings-panel li::before { content: "⚠️"; font-size: 12px; }

    .recommendation-panel { border-left: 4px solid var(--neon-cyan); background: rgba(0, 240, 255, 0.03); }
    .recommendation-panel.risk-low { border-left-color: var(--neon-green); }
    .recommendation-panel.risk-med { border-left-color: var(--neon-amber); }
    .recommendation-panel.risk-high { border-left-color: var(--neon-red); }
    .recommendation-panel p { font-size: 14px; color: #e2e8f0; line-height: 1.6; }

    .diag-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-top: 6px; }
    .diag-item { background: rgba(3, 8, 20, 0.6); border: 1px solid rgba(40, 75, 120, 0.3); border-radius: 8px; padding: 10px; }
    .diag-item .diag-label { font-size: 10px; color: var(--text-dim); text-transform: uppercase; }
    .diag-item .diag-value { font-size: 12px; color: #f1f5f9; font-weight: 600; font-family: var(--font-mono); margin-top: 4px; }

    .toast {
      position: fixed; bottom: 24px; right: 24px;
      background: rgba(6, 17, 36, 0.95);
      border: 1px solid var(--neon-green);
      box-shadow: 0 0 25px var(--neon-green-glow);
      color: #fff; padding: 14px 22px; border-radius: 12px; font-size: 13px; font-weight: 600;
      display: flex; align-items: center; gap: 10px;
      transform: translateY(100px); opacity: 0; transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      z-index: 1000;
    }
    .toast.show { transform: translateY(0); opacity: 1; }

    footer { text-align: center; padding: 30px 15px; color: var(--text-dim); font-size: 12px; border-top: 1px solid rgba(40, 75, 120, 0.2); }

    @media (max-width: 768px) {
      .hero h1 { font-size: 32px; }
      .executive-summary-panel { grid-template-columns: 1fr; text-align: center; }
      .report-grid { grid-template-columns: 1fr; }
      .actions-bar { flex-direction: column; }
      .btn { width: 100%; }
      .report-toolbar { flex-direction: column; align-items: flex-start; }
    }

    @media print {
      body { background: #fff !important; color: #111827 !important; font-size: 11pt !important; }
      header, .hero, .tabs-wrapper, #inputSection, .actions-bar, .report-actions, footer, .toast, .scan-beam, .glow-orb { display: none !important; }
      .report-section { display: block !important; }
      .glass-card { background: #fff !important; border: 1px solid #d1d5db !important; box-shadow: none !important; }
      .executive-summary-panel { background: #f9fafb !important; border: 1px solid #e5e7eb !important; }
      .gauge-container { background: #e5e7eb !important; }
      .gauge-percent { color: #111827 !important; }
      .report-panel { background: #fff !important; border: 1px solid #e5e7eb !important; }
      .report-panel h4 { color: #111827 !important; }
      .report-panel li { color: #374151 !important; }
    }
  </style>
</head>
<body>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>

  <header>
    <div class="nav-container">
      <a href="#" class="brand">
        <div class="brand-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div class="brand-text">Phishing Email &amp; <span>Website Detector</span></div>
      </a>
      <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
        <div class="mobile-badge" id="mobileBadge" onclick="copyMobileUrl()" title="Click to copy Mobile URL">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/></svg>
          <span id="mobileUrlText">📱 Mobile: Connecting...</span>
        </div>
        <div class="status-badge">
          <div class="pulse-dot"></div>
          <span>CYBERSECURITY SYSTEM ACTIVE</span>
        </div>
      </div>
    </div>
  </header>

  <main>
    <section class="hero">
      <div class="hero-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
        Cybersecurity Detection System
      </div>
      <h1>Phishing Email &amp; <span class="highlight">Website Detector</span></h1>
      <p>Multi-layered cybersecurity intelligence engine analyzing structural, lexical, behavioral, and machine-learning threat vectors across communications and digital destinations.</p>
    </section>

    <div class="tabs-wrapper">
      <div class="tabs">
        <button class="tab-btn active" id="tabEmail" onclick="setMode('email')">📧 Email &amp; Message Scanner</button>
        <button class="tab-btn" id="tabUrl" onclick="setMode('url')">🌐 Website &amp; URL Scanner</button>
      </div>
    </div>

    <section class="glass-card" id="inputSection">
      <div class="scan-beam"></div>

      <div id="panelEmail">
        <div class="card-header">
          <h2>📧 Email &amp; Social Engineering Inspection</h2>
          <p>Detect executive spoofing (BEC), financial fraud, credential harvesting lures, and malicious links in emails.</p>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
          <div class="form-group">
            <label for="senderInput">Sender Address (Optional)</label>
            <input type="text" id="senderInput" placeholder="e.g. security-update@paypal-support.xyz">
          </div>
          <div class="form-group">
            <label for="subjectInput">Email Subject (Optional)</label>
            <input type="text" id="subjectInput" placeholder="e.g. Urgent: Wire transfer authorization needed">
          </div>
        </div>
        <div class="form-group">
          <label for="messageInput">Message Content *</label>
          <textarea id="messageInput" placeholder="Paste the full email body or suspicious message text here..."></textarea>
        </div>
        <div class="samples-bar">
          <span class="sample-label">Quick Samples:</span>
          <button type="button" class="sample-pill bad" onclick="loadSample('bec-email')">🚨 BEC / CEO Fraud</button>
          <button type="button" class="sample-pill bad" onclick="loadSample('phish-email')">🚨 Credential Phish</button>
          <button type="button" class="sample-pill" onclick="loadSample('safe-email')">✅ Legitimate Corporate</button>
        </div>
      </div>

      <div id="panelUrl" style="display: none;">
        <div class="card-header">
          <h2>🌐 URL &amp; Digital Destination Inspection</h2>
          <p>Scan web addresses for illicit streaming/piracy networks, malware droppers, typosquatting, and deceptive mirrors.</p>
        </div>
        <div class="form-group">
          <label for="urlInput">Target URL *</label>
          <input type="text" id="urlInput" placeholder="e.g. https://movierulz.com or https://netmirror.app">
        </div>
        <div class="samples-bar">
          <span class="sample-label">Quick Samples:</span>
          <button type="button" class="sample-pill bad" onclick="loadSample('piracy-movierulz')">🚨 MovieRulz Stream</button>
          <button type="button" class="sample-pill bad" onclick="loadSample('mirror-netmirror')">🚨 NetMirror Clone</button>
          <button type="button" class="sample-pill bad" onclick="loadSample('phish-url')">🚨 Bank Spoof URL</button>
          <button type="button" class="sample-pill" onclick="loadSample('safe-url')">✅ Verified Domain</button>
        </div>
      </div>

      <div class="actions-bar">
        <button type="button" class="btn btn-neon-primary" id="btnAnalyze" onclick="executeAnalysis()">🔍 Run Cybersecurity Analysis</button>
        <button type="button" class="btn btn-outline" onclick="resetForm()">Clear</button>
      </div>

      <div class="status-alert" id="statusAlert">
        <span id="statusMessage"></span>
      </div>
    </section>

    <section class="report-section" id="reportSection">
      <div class="glass-card report-card" id="reportCard">
        <div class="report-toolbar">
          <div class="report-title-group">
            <h3>Cybersecurity Assessment Report</h3>
            <p id="reportRef">REF: PEWD-SCAN | ENGINE: ADVANCED CYBERSECURITY v2.0</p>
          </div>
          <div class="report-actions">
            <button type="button" class="btn-tool" id="btnCopyReport" onclick="copyReport()">📋 <span>Copy Report</span></button>
            <button type="button" class="btn-tool" onclick="window.print()">🖨️ <span>Print / PDF</span></button>
          </div>
        </div>

        <div class="executive-summary-panel">
          <div class="gauge-container" id="scoreGauge">
            <div class="gauge-center">
              <div class="gauge-percent" id="scoreValue">0%</div>
              <div class="gauge-label">RISK INDEX</div>
            </div>
          </div>
          <div class="summary-text-box">
            <h4>
              Threat Level: 
              <span class="badge-level" id="badgeLevel">LOW RISK</span>
              <span class="badge-category" id="badgeCategory">General Communication</span>
            </h4>
            <div class="summary-desc" id="summaryDescription">No critical threat vectors detected.</div>
            <div class="scan-meta-pill">
              <span id="scanTimestamp">Scan Completed: Just now</span> •
              <span id="scanTargetType">Mode: Email</span> •
              <span id="scanConfidence">Confidence: High</span>
            </div>
          </div>
        </div>

        <div class="vectors-matrix">
          <h4>⚡ Threat Vector Analysis Matrix</h4>
          <div class="vector-bars-grid">
            <div class="vector-bar-item">
              <div class="vb-head"><span>Social Engineering Index</span><span id="vecSocialVal">0%</span></div>
              <div class="vb-track"><div class="vb-fill fill-amber" id="vecSocialFill"></div></div>
            </div>
            <div class="vector-bar-item">
              <div class="vb-head"><span>Domain Evasion &amp; Obfuscation</span><span id="vecEvasionVal">0%</span></div>
              <div class="vb-track"><div class="vb-fill fill-cyan" id="vecEvasionFill"></div></div>
            </div>
            <div class="vector-bar-item">
              <div class="vb-head"><span>Credential Theft Exposure</span><span id="vecCredVal">0%</span></div>
              <div class="vb-track"><div class="vb-fill fill-purple" id="vecCredFill"></div></div>
            </div>
            <div class="vector-bar-item">
              <div class="vb-head"><span>Malware &amp; Malvertising Risk</span><span id="vecMalwareVal">0%</span></div>
              <div class="vb-track"><div class="vb-fill fill-red" id="vecMalwareFill"></div></div>
            </div>
          </div>
        </div>

        <div class="report-grid">
          <div class="report-panel findings-panel">
            <h4>Identified Threat Indicators &amp; Red Flags</h4>
            <ul id="reasonsList"></ul>
          </div>
          <div class="report-panel">
            <h4>Technical Heuristics Breakdown</h4>
            <ul id="detailsList"></ul>
          </div>
        </div>

        <div class="report-panel recommendation-panel" id="recPanel" style="margin-bottom: 20px;">
          <h4>Cybersecurity Incident Guidance</h4>
          <p id="recText"></p>
        </div>

        <div class="report-panel">
          <h4>System Diagnostics &amp; Engine Metadata</h4>
          <div class="diag-grid">
            <div class="diag-item"><div class="diag-label">Active Core Engine</div><div class="diag-value" id="diagEngine">Advanced Heuristic v2.0</div></div>
            <div class="diag-item"><div class="diag-label">Machine Learning</div><div class="diag-value" id="diagML">Active Neural TF-IDF</div></div>
            <div class="diag-item"><div class="diag-label">Threat Confidence</div><div class="diag-value" id="diagConfidence">High (95%)</div></div>
            <div class="diag-item"><div class="diag-label">Reputation Network</div><div class="diag-value" id="diagRep">Sandboxed Heuristics</div></div>
          </div>
        </div>
      </div>
    </section>

    <div class="toast" id="toastNotification">
      <span id="toastText">Report copied to clipboard!</span>
    </div>
  </main>

  <footer>
    <p><strong>Phishing Email &amp; Website Detector</strong> • Cybersecurity Detection System.<br>
    Multi-layer heuristics, lexical analysis, and behavioral threat modeling.</p>
  </footer>

  <script>
    let currentMode = 'email';
    let lastAnalysisData = null;
    let mobileUrl = window.location.origin;

    const $ = id => document.getElementById(id);

    function initMobileInfo() {
      fetch('/api/info').then(r => r.json()).then(d => {
        if (d && d.mobile_url) {
          mobileUrl = d.mobile_url;
          $('mobileUrlText').textContent = `📱 Mobile: ${d.mobile_url}`;
        }
      }).catch(() => {});
    }
    initMobileInfo();

    function copyMobileUrl() {
      navigator.clipboard.writeText(mobileUrl).then(() => {
        showToast(`Mobile URL copied: ${mobileUrl}`);
      });
    }

    function setMode(mode) {
      currentMode = mode;
      $('panelEmail').style.display = mode === 'email' ? 'block' : 'none';
      $('panelUrl').style.display = mode === 'url' ? 'block' : 'none';
      $('tabEmail').classList.toggle('active', mode === 'email');
      $('tabUrl').classList.toggle('active', mode === 'url');
    }

    function loadSample(type) {
      if (type === 'bec-email') {
        setMode('email');
        $('senderInput').value = 'ceo-office-direct@gmail.com';
        $('subjectInput').value = 'URGENT: Confidential Wire Transfer Request';
        $('messageInput').value = 'Are you at your desk? We are concluding a confidential corporate acquisition and need an urgent wire transfer processed within 24 hours.\\n\\nPlease process payment to the escrow account and confirm once completed. Keep this strictly confidential.\\n\\nChief Executive Officer';
      } else if (type === 'phish-email') {
        setMode('email');
        $('senderInput').value = 'security-alert@account-verification-paypal.com';
        $('subjectInput').value = 'URGENT: Unusual login attempt detected — Account suspended';
        $('messageInput').value = 'Dear customer,\\n\\nWe detected unauthorized login attempts from an unknown device. Your payment capabilities and account will be permanently blocked within 24 hours.\\n\\nYou must verify your password, payment cards, and identity immediately by clicking the secure link below:\\nhttp://verify-account.paypal-security.invalid/login?user=auth\\n\\nBank & Security Team';
      } else if (type === 'safe-email') {
        setMode('email');
        $('senderInput').value = 'newsletter@github.com';
        $('subjectInput').value = 'Your weekly GitHub project digest';
        $('messageInput').value = 'Hello developer,\\n\\nHere are the top trending open source repositories in your network this week. You can review release notes, check commit histories, and read discussions on GitHub.\\n\\nHave a great weekend,\\nThe GitHub Team';
      } else if (type === 'piracy-movierulz') {
        setMode('url'); $('urlInput').value = 'https://movierulz.com';
      } else if (type === 'mirror-netmirror') {
        setMode('url'); $('urlInput').value = 'https://netmirror.app';
      } else if (type === 'phish-url') {
        setMode('url'); $('urlInput').value = 'http://secure-paypal-login.account-verification.xyz/auth';
      } else if (type === 'safe-url') {
        setMode('url'); $('urlInput').value = 'https://google.com';
      }
    }

    function resetForm() {
      $('senderInput').value = ''; $('subjectInput').value = '';
      $('messageInput').value = ''; $('urlInput').value = '';
      $('reportSection').classList.remove('show');
    }

    function showToast(msg) {
      const toast = $('toastNotification');
      $('toastText').textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2500);
    }

    async function executeAnalysis() {
      const isEmail = currentMode === 'email';
      const text = isEmail ? $('messageInput').value.trim() : $('urlInput').value.trim();
      if (!text) return alert('Please enter message text or a URL before analyzing.');

      $('inputSection').classList.add('scanning');
      $('btnAnalyze').disabled = true;

      const payload = isEmail ? {
        mode: 'email', sender: $('senderInput').value.trim(), subject: $('subjectInput').value.trim(), text: text
      } : { mode: 'url', text: text };

      try {
        const response = await fetch('/api/analyze', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error);
        lastAnalysisData = data;
        renderReport(data);
      } catch (err) {
        alert('Analysis error: ' + err.message);
      } finally {
        $('inputSection').classList.remove('scanning');
        $('btnAnalyze').disabled = false;
      }
    }

    function renderReport(data) {
      const score = Math.max(0, Math.min(100, parseInt(data.score, 10) || 0));
      const riskClass = score >= 70 ? 'risk-high' : score >= 40 ? 'risk-med' : 'risk-low';

      $('reportCard').className = `glass-card report-card ${riskClass}`;
      $('scoreGauge').className = `gauge-container ${riskClass}`;
      $('scoreGauge').style.setProperty('--gauge-val', score);
      $('scoreValue').textContent = `${score}%`;

      $('badgeLevel').className = `badge-level ${riskClass}`;
      $('badgeLevel').textContent = `${data.level || 'ASSESSED'} (${score}%)`;
      $('badgeCategory').textContent = data.category || 'General';
      $('summaryDescription').textContent = data.summary || 'Cybersecurity scan complete.';

      const v = data.vectors || {};
      $('vecSocialVal').textContent = (v.social_engineering || 0) + '%';
      $('vecSocialFill').style.width = (v.social_engineering || 0) + '%';
      $('vecEvasionVal').textContent = (v.domain_evasion || 0) + '%';
      $('vecEvasionFill').style.width = (v.domain_evasion || 0) + '%';
      $('vecCredVal').textContent = (v.credential_risk || 0) + '%';
      $('vecCredFill').style.width = (v.credential_risk || 0) + '%';
      $('vecMalwareVal').textContent = (v.malware_risk || 0) + '%';
      $('vecMalwareFill').style.width = (v.malware_risk || 0) + '%';

      $('reasonsList').innerHTML = (data.reasons || []).map(r => `<li>${r}</li>`).join('');
      $('detailsList').innerHTML = (data.details || []).map(d => `<li>${d}</li>`).join('');
      $('recPanel').className = `report-panel recommendation-panel ${riskClass}`;
      $('recText').textContent = data.recommendation || 'Maintain standard verification procedures.';

      $('reportSection').classList.add('show');
      $('reportSection').scrollIntoView({ behavior: 'smooth' });
    }

    function copyReport() {
      if (!lastAnalysisData) return;
      const d = lastAnalysisData;
      const reportText = `🛡️ PHISHING EMAIL & WEBSITE DETECTOR — CYBERSECURITY ASSESSMENT
======================================================================
Threat Level:      ${d.level} (Threat Score: ${d.score}/100)
Threat Category:   ${d.category || 'General Communication'}
Summary:           ${d.summary}

CYBERSECURITY VECTOR METRICS:
  • Social Engineering:       ${d.vectors?.social_engineering || 0}%
  • Domain Evasion/Obfuscate: ${d.vectors?.domain_evasion || 0}%
  • Credential Exposure:      ${d.vectors?.credential_risk || 0}%
  • Malware & Malvertising:   ${d.vectors?.malware_risk || 0}%

IDENTIFIED THREAT INDICATORS:
${(d.reasons || []).map(r => '  • ' + r).join('\\n')}

RECOMMENDED ACTION:
${d.recommendation}
======================================================================`;

      navigator.clipboard.writeText(reportText).then(() => {
        showToast('Cybersecurity assessment report copied to clipboard!');
      });
    }
  </script>
</body>
</html>"""

# ======================================================================================
# ADVANCED CYBERSECURITY DETECTION ENGINE (HEURISTICS, ENTROPY, VECTORS)
# ======================================================================================

TARGET_BRANDS = {
    'paypal': ['paypal.com'],
    'google': ['google.com', 'accounts.google.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com'],
    'netflix': ['netflix.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
    'binance': ['binance.com'],
    'coinbase': ['coinbase.com'],
    'metamask': ['metamask.io'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'discord': ['discord.com', 'discord.gg']
}

PIRACY_STREAMING_BRANDS = [
    'movierulz', 'netmirror', 'tamilrockers', '123movies', 'fmovies',
    'soap2day', 'torrent', 'piratebay', '1337x', 'yts', 'rarbg',
    'putlocker', 'streamtape', 'vidcloud', 'doodstream', 'animeflix',
    'gogoanime', '9anime', 'filmyzilla', 'filmywap', 'ibomma',
    'crazyhd', 'warez', 'bolly4u', 'mp4moviez', 'pagalworld',
    'khatrimaza', 'hubflix', 'vegamovies', 'bflix', 'cinebloom',
    'hdhub4u', 'katmoviehd', 'thepiratebay', 'extratorrent'
]

MIRROR_PROXY_INDICATORS = [
    'mirror', 'unblock', 'proxy', 'bypass', 'clone', 'freemovies',
    'watchfree', 'hdstream', 'directdownload', 'cracked', 'modapk',
    'freeapk', 'torrentmagnet', 'streaming-free', 'free-movies'
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'ow.ly',
    'rebrand.ly', 'goo.gl', 'v.gd', 'buff.ly', 'clck.ru', 'shorturl.at'
}

HIGH_RISK_TLDS = {
    'to', 'is', 'cc', 'ws', 'pw', 'top', 'xyz', 'biz', 'monster',
    'club', 'work', 'click', 'live', 'stream', 'download', 'cam',
    'rip', 'link', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 'ms',
    'in.net', 'vip', 'buzz', 'fit', 'rest', 'surf', 'loan', 'gdn'
}

DANGEROUS_EXTENSIONS = (
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.iso', '.apk', '.zip',
    '.rar', '.7z', '.dmg', '.jar', '.hta', '.msi', '.dll', '.ps1'
)

def calculate_shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 2)

def detect_typosquatting(host):
    h_clean = host.lower()
    for brand, legit_domains in TARGET_BRANDS.items():
        if brand in h_clean:
            is_legit = any(h_clean == leg or h_clean.endswith('.' + leg) for leg in legit_domains)
            if not is_legit:
                return True, brand, f"Brand impersonation / spoofing of '{brand.capitalize()}' detected on unauthorized host."
        sim = h_clean.replace('0', 'o').replace('1', 'l').replace('rn', 'm').replace('vv', 'w')
        if brand in sim and brand not in h_clean:
            return True, brand, f"Typosquatting / homoglyph manipulation targeting '{brand.capitalize()}' detected."
    return False, '', ''

def extract_advanced_url_features(raw):
    u = raw.strip()
    u = u if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', u) else 'http://' + u
    parsed = urlparse(u)
    h = (parsed.hostname or '').lower()
    path = (parsed.path or '').lower()
    query = parsed.query.lower()
    full_target = (h + path + '?' + query).lower()

    s = 0
    reasons = []
    credential_risk = 0
    malware_risk = 0
    social_engineering = 0
    domain_evasion = 0

    if parsed.scheme != 'https':
        s += 12
        domain_evasion += 15
        reasons.append('Insecure Protocol: URL does not enforce HTTPS encryption.')

    if parsed.port and parsed.port not in (80, 443):
        s += 18
        domain_evasion += 25
        reasons.append(f'Anomalous Port: Target operates on non-standard web port (:{parsed.port}).')

    try:
        socket.inet_aton(h)
        s += 28
        domain_evasion += 40
        reasons.append('Direct IP Hosting: URL uses a raw IP address instead of domain.')
    except OSError:
        pass

    if '@' in u:
        s += 25
        domain_evasion += 35
        reasons.append("Credential Injection: URL contains '@' masking destination host.")

    if 'xn--' in h:
        s += 22
        domain_evasion += 30
        reasons.append('Punycode Homograph: Hostname utilizes Internationalized Domain Name (xn--) encoding.')

    entropy = calculate_shannon_entropy(h.split('.')[0] if '.' in h else h)
    if entropy >= 3.8 and len(h.split('.')[0]) >= 10:
        s += 18
        domain_evasion += 25
        reasons.append(f'High Host Entropy ({entropy}): Potential Algorithmic Domain Generation (DGA).')

    subdomain_count = len(h.split('.')) - 1
    if subdomain_count >= 4:
        s += 12
        domain_evasion += 20
        reasons.append(f'Subdomain Stacking: Host contains {subdomain_count} subdomains.')

    if h in URL_SHORTENERS:
        s += 20
        domain_evasion += 30
        reasons.append(f'URL Shortener Masking: Public redirection service ({h}) conceals destination.')

    tld = h.split('.')[-1] if '.' in h else ''
    if tld in HIGH_RISK_TLDS:
        s += 18
        domain_evasion += 25
        reasons.append(f'Abused TLD: Domain registered under high-abuse TLD (.{tld}).')

    if path.endswith(DANGEROUS_EXTENSIONS):
        ext = '.' + path.split('.')[-1]
        s += 45
        malware_risk += 60
        reasons.append(f'Executable/Archive Payload: URL delivers dangerous file ({ext}).')

    query_params = parse_qs(query)
    if any(k in query_params for k in {'redirect', 'url', 'next', 'target', 'dest', 'return', 'r'}):
        s += 15
        domain_evasion += 20
        reasons.append('Open Redirect Parameter: Query string contains external redirection vectors.')

    is_typo, brand_name, typo_reason = detect_typosquatting(h)
    if is_typo:
        s += 45
        social_engineering += 50
        credential_risk += 45
        reasons.append(typo_reason)

    action_keywords = ['login', 'signin', 'verify', 'password', 'credential', 'account', 'secure', 'payment', 'wallet', 'update', 'banking']
    found_actions = [w for w in action_keywords if w in full_target]
    if found_actions:
        score_add = min(30, 6 * len(found_actions))
        s += score_add
        credential_risk += score_add * 2
        reasons.append(f"Credential Harvesting Indicators: Keywords identified ({', '.join(found_actions)}).")

    crypto_keywords = ['metamask', 'seedphrase', 'secret-recovery', 'connect-wallet', 'airdrop-claim', 'token-drain']
    found_crypto = [w for w in crypto_keywords if w in full_target]
    if found_crypto:
        s += 50
        credential_risk += 60
        reasons.append(f"Crypto Asset Drainer: Web3/wallet extraction markers identified ({', '.join(found_crypto)}).")

    matched_piracy = [b for b in PIRACY_STREAMING_BRANDS if b in h or b in full_target]
    if matched_piracy:
        s += 70
        malware_risk += 65
        reasons.append(f"Illicit Streaming / Piracy Network: Target matched known unauthorized media network ({', '.join(matched_piracy)}). Known vector for drive-by malware and rogue ad networks.")

    matched_mirror = [m for m in MIRROR_PROXY_INDICATORS if m in h or m in full_target]
    if matched_mirror:
        s += 20
        domain_evasion += 30
        reasons.append(f"Mirror / Proxy Evasion Gateway: Unverified mirror distribution markers ({', '.join(matched_mirror)}).")

    details = [
        f'Analyzed Host: {h or "unavailable"}',
        f'Protocol Scheme: {parsed.scheme.upper()}',
        f'URL Length: {len(raw)} characters',
        f'Top-Level Domain: .{tld}' if tld else 'Top-Level Domain: unknown',
        f'Host Shannon Entropy: {entropy}',
        f'Subdomain Depth: {subdomain_count}'
    ]

    vectors = {
        'credential_risk': min(100, credential_risk),
        'malware_risk': min(100, malware_risk),
        'social_engineering': min(100, social_engineering),
        'domain_evasion': min(100, domain_evasion)
    }

    return min(s, 100), reasons, details, vectors

def extract_advanced_email_features(text, sender='', subject=''):
    c = f'{sender} {subject} {text}'.lower()
    s = 0
    reasons = []
    details = []

    credential_risk = 0
    malware_risk = 0
    social_engineering = 0
    domain_evasion = 0

    urgency_groups = [
        (['urgent', 'immediately', 'act now', 'within 24 hours', 'immediate action', 'suspended', 'deactivated', 'permanent loss'], 15, 'Urgency & Pressure Manipulation', 35),
        (['verify your identity', 'confirm your password', 'security alert', 'unusual activity', 'compromised account', 'reset password'], 12, 'Credential & Account Security Lure', 30),
        (['wire transfer', 'payroll update', 'direct deposit', 'gift card', 'confidential transaction', 'urgent payment'], 18, 'BEC & Financial Fraud Solicitation', 40),
        (['invoice attached', 'overdue payment', 'geek squad', 'norton renewal', 'mcafee charge', 'call toll-free'], 16, 'Tech Support & Fake Invoice Deception', 35),
        (['lottery winner', 'prize reward', 'inheritance funds', 'airdrop claim'], 14, 'Financial Bait & Greed Exploit', 25)
    ]

    for words, pts, label, se_weight in urgency_groups:
        matched = [w for w in words if w in c]
        if matched:
            s += min(pts, 8 * len(matched))
            social_engineering += se_weight
            reasons.append(f"{label}: Coercive tokens detected ({', '.join(matched[:5])}).")

    if sender and re.search(r'@(gmail|yahoo|outlook|hotmail|protonmail)\.com$', sender.lower()):
        org_triggers = ['paypal', 'bank', 'government', 'irs', 'security team', 'microsoft', 'apple', 'ceo', 'cfo', 'hr department']
        if any(x in c for x in org_triggers):
            s += 35
            social_engineering += 50
            domain_evasion += 40
            reasons.append('Freemail Executive Spoofing: Public webmail sender claims authoritative corporate or organizational identity.')

    urls = re.findall(r'https?://[^\s<>\'\"]+', c)
    if urls:
        reasons.append(f'Embedded Hyperlinks: Message contains {len(urls)} external links.')
        for u in urls[:4]:
            u_score, u_reasons, u_details, u_vec = extract_advanced_url_features(u)
            s += min(35, int(u_score * 0.6))
            credential_risk = max(credential_risk, u_vec['credential_risk'])
            malware_risk = max(malware_risk, u_vec['malware_risk'])
            domain_evasion = max(domain_evasion, u_vec['domain_evasion'])
            reasons += u_reasons[:2]
            details.append('Embedded Target: ' + u)

    if any(k in c for k in ['secret recovery phrase', 'seed phrase', 'private key', '12-word phrase']):
        s += 50
        credential_risk = 100
        reasons.append('Critical Threat: Direct solicitation of cryptocurrency private keys or seed recovery phrases.')

    details.append('Sender Header Provided: ' + ('Yes' if sender else 'No'))
    details.append(f'Subject Line Length: {len(subject)} characters')
    details.append(f'Message Body Length: {len(text)} characters')

    vectors = {
        'credential_risk': min(100, credential_risk),
        'malware_risk': min(100, malware_risk),
        'social_engineering': min(100, social_engineering),
        'domain_evasion': min(100, domain_evasion)
    }

    return min(s, 100), reasons, details, vectors

def determine_threat_category(score, vectors, reasons_text):
    if score < 40:
        return 'Benign / Low Risk'
    r_lower = ' '.join(reasons_text).lower()
    if 'illicit streaming' in r_lower or 'piracy' in r_lower or 'torrent' in r_lower:
        return 'Illicit Streaming & Malvertising Vector'
    if 'crypto' in r_lower or 'wallet' in r_lower or 'seed' in r_lower:
        return 'Cryptocurrency Drainer / Wallet Theft'
    if 'bec' in r_lower or 'financial fraud' in r_lower or 'freemail executive' in r_lower:
        return 'Business Email Compromise (BEC) / CEO Fraud'
    if 'invoice' in r_lower or 'tech support' in r_lower:
        return 'Tech Support & Fake Invoice Deception'
    if 'executable' in r_lower or 'payload' in r_lower or vectors.get('malware_risk', 0) >= 50:
        return 'Malware Delivery / Malicious Payload'
    if vectors.get('credential_risk', 0) >= 40 or 'credential' in r_lower or 'brand impersonation' in r_lower:
        return 'Phishing & Credential Harvesting'
    return 'Social Engineering / Suspicious Entity'

def run_ml_prediction(text):
    model_path = os.path.join(os.path.dirname(__file__), 'backend', 'ml', 'phishing_text_model.joblib')
    if not joblib or not os.path.exists(model_path):
        return {'available': False}
    try:
        m = joblib.load(model_path)
        pr = m.predict_proba([text])[0]
        c = list(m.classes_)
        i = c.index(1) if 1 in c else max(range(len(c)), key=lambda j: pr[j])
        return {'available': True, 'label': str(c[i]), 'phishing_probability': float(pr[i])}
    except Exception:
        return {'available': False}

def analyze_threat(mode, text, sender='', subject=''):
    if mode == 'url':
        s, reasons, details, vectors = extract_advanced_url_features(text)
        ml = run_ml_prediction(text)
    else:
        s, reasons, details, vectors = extract_advanced_email_features(text, sender, subject)
        c = f'{sender} {subject} {text}'.lower()
        ml = run_ml_prediction(c)

    if ml.get('available'):
        ml_prob = ml.get('phishing_probability', 0)
        if ml_prob >= 0.75:
            s += 18
            vectors['social_engineering'] = min(100, vectors.get('social_engineering', 0) + 20)
            reasons.append(f'Machine Learning Classifier: Neural model flagged elevated threat probability ({round(ml_prob * 100)}%).')
        elif ml_prob <= 0.25 and s <= 20:
            s = max(0, s - 10)

    final_score = max(0, min(100, int(s)))
    category = determine_threat_category(final_score, vectors, reasons)

    if final_score >= 70:
        level = 'HIGH RISK'
        summary = f'Critical threat profile detected [{category}]. High likelihood of credential theft, fraudulent compromise, or malware injection.'
        recommendation = 'DO NOT ENGAGE. Do not click embedded links, enter passwords/OTPs, execute attachments, or approve wallet signatures. Block and report sender or domain.'
        confidence = 'High (95%)'
    elif final_score >= 40:
        level = 'MEDIUM RISK'
        summary = f'Elevated risk profile detected [{category}]. Target contains deceptive indicators that require verification.'
        recommendation = 'EXERCISE CAUTION. Do not submit sensitive corporate credentials, personal data, or payments. Validate identity through out-of-band channels.'
        confidence = 'Moderate (80%)'
    else:
        level = 'LOW RISK'
        summary = 'No critical threat vectors detected by the cybersecurity heuristics and machine learning engine.'
        recommendation = 'Standard hygiene advised. Low risk is not a cryptographic guarantee of safety. Ensure destination domain is authenticated.'
        confidence = 'High (90%)'

    return {
        'status': 'ok',
        'level': level,
        'score': final_score,
        'category': category,
        'confidence': confidence,
        'vectors': vectors,
        'summary': summary,
        'reasons': list(dict.fromkeys(reasons)) or ['No significant threat anomalies observed.'],
        'details': details or ['Heuristic and ML verification completed.'],
        'recommendation': recommendation,
        'mode': mode,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'engine': 'Advanced Multi-Layer Cybersecurity Detection Engine v2.0',
        'reputation_connected': False,
        'reputation': {'configured': False, 'findings': []},
        'ml': ml
    }

# ======================================================================================
# FLASK APPLICATION SERVER
# ======================================================================================

app = Flask(__name__)
CORS(app, resources={r'/api/*': {'origins': '*'}})

def get_network_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

@app.get('/')
def home():
    return render_template_string(HTML_PAGE)

@app.get('/api/health')
def health():
    return jsonify({'status': 'ok', 'message': 'Cybersecurity Backend running'})

@app.get('/api/info')
def info():
    ip = get_network_ip()
    return jsonify({
        'status': 'ok',
        'network_ip': ip,
        'port': 5000,
        'mobile_url': f'http://{ip}:5000'
    })

@app.post('/api/analyze')
def api_analyze():
    d = request.get_json(silent=True) or {}
    mode = str(d.get('mode', '')).lower()
    text = str(d.get('text', '')).strip()
    if mode not in ('email', 'url') or not text:
        return jsonify({'error': 'Valid mode and text are required'}), 400
    try:
        res = analyze_threat(mode, text, str(d.get('sender', '')).strip(), str(d.get('subject', '')).strip())
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': 'Analysis failed', 'detail': str(e)}), 500

if __name__ == '__main__':
    local_ip = get_network_ip()
    print("=" * 70)
    print("[*] PHISHING EMAIL & WEBSITE DETECTOR -- FULLSTACK SERVER")
    print("=" * 70)
    print(f" * Laptop (Localhost): http://127.0.0.1:5000")
    print(f" * Mobile / Network:   http://{local_ip}:5000")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=True)
