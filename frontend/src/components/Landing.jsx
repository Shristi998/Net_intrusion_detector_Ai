import React from 'react';
import { Shield, BrainCircuit, Activity, Lock, ArrowRight, Moon, Sun } from 'lucide-react';

export default function Landing({ onEnter, theme, toggleTheme }) {
  const isDark = theme === 'dark';

  return (
    <div className="landing-root">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap');

        .landing-root {
          font-family: 'Outfit', sans-serif;
          min-height: 100vh;
          background: ${isDark ? '#0f172a' : '#f8fafc'};
          position: relative;
          overflow: hidden;
          color: ${isDark ? '#f8fafc' : '#0f172a'};
          display: flex;
          flex-direction: column;
          transition: background 0.3s ease, color 0.3s ease;
        }

        /* Animated Mesh Gradient Background */
        .landing-root::before, .landing-root::after {
          content: '';
          position: absolute;
          border-radius: 50%;
          filter: blur(100px);
          z-index: 0;
          animation: floatSlow 15s ease-in-out infinite alternate;
        }
        
        .landing-root::before {
          width: 800px;
          height: 800px;
          background: rgba(56, 189, 248, 0.12); /* Light Blue */
          top: -200px;
          left: -200px;
        }
        
        .landing-root::after {
          width: 600px;
          height: 600px;
          background: rgba(167, 139, 250, 0.12); /* Light Purple */
          bottom: -100px;
          right: -100px;
          animation-delay: -7s;
        }

        @keyframes floatSlow {
          0% { transform: translate(0, 0) scale(1); }
          100% { transform: translate(50px, 80px) scale(1.05); }
        }

        .navbar {
          position: relative;
          z-index: 10;
          padding: 24px 48px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          animation: slideDown 0.8s ease;
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 12px;
          font-size: 24px;
          font-weight: 700;
          letter-spacing: -0.5px;
          color: inherit;
        }

        .brand-icon-wrap {
          width: 48px;
          height: 48px;
          background: linear-gradient(135deg, #38bdf8 0%, #2563eb 100%);
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);
        }

        .nav-actions {
          display: flex;
          align-items: center;
          gap: 16px;
        }

        .theme-btn {
          background: transparent;
          border: none;
          color: ${isDark ? '#94a3b8' : '#475569'};
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 8px;
          border-radius: 50%;
          transition: all 0.2s;
        }

        .theme-btn:hover {
          background: ${isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.05)'};
          color: ${isDark ? '#f8fafc' : '#0f172a'};
        }

        .nav-btn {
          background: ${isDark ? 'rgba(30, 41, 59, 0.6)' : 'rgba(255, 255, 255, 0.6)'};
          backdrop-filter: blur(12px);
          border: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(255, 255, 255, 0.8)'};
          color: inherit;
          padding: 10px 24px;
          border-radius: 20px;
          font-weight: 600;
          font-size: 14px;
          cursor: pointer;
          transition: all 0.2s ease;
          box-shadow: 0 4px 12px rgba(0,0,0,0.02);
        }

        .nav-btn:hover {
          background: ${isDark ? '#1e293b' : 'white'};
          transform: translateY(-1px);
          box-shadow: 0 6px 16px rgba(0,0,0,0.04);
        }

        .hero-section {
          position: relative;
          z-index: 10;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          flex: 1;
          padding: 40px 20px;
          text-align: center;
          animation: slideUp 0.8s ease;
        }

        .pill-badge {
          background: rgba(56, 189, 248, 0.1);
          color: ${isDark ? '#38bdf8' : '#0284c7'};
          padding: 6px 16px;
          border-radius: 20px;
          font-size: 13px;
          font-weight: 600;
          margin-bottom: 24px;
          border: 1px solid rgba(56, 189, 248, 0.2);
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }

        .hero-title {
          font-size: 64px;
          font-weight: 800;
          line-height: 1.1;
          letter-spacing: -2px;
          margin-bottom: 24px;
          max-width: 800px;
          color: inherit;
        }

        .hero-title span {
          background: linear-gradient(135deg, #2563eb 0%, #38bdf8 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }

        .hero-desc {
          font-size: 20px;
          color: ${isDark ? '#94a3b8' : '#475569'};
          max-width: 600px;
          line-height: 1.6;
          margin-bottom: 48px;
        }

        .cta-btn {
          background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
          color: white;
          border: none;
          padding: 18px 40px;
          border-radius: 30px;
          font-size: 18px;
          font-weight: 600;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 12px;
          transition: all 0.2s ease;
          box-shadow: 0 10px 25px rgba(37, 99, 235, 0.25);
        }

        .cta-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 15px 35px rgba(37, 99, 235, 0.35);
        }
        
        .cta-btn:active {
          transform: translateY(1px);
        }

        .features-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 24px;
          max-width: 1100px;
          margin: 0 auto 60px;
          position: relative;
          z-index: 10;
          padding: 0 24px;
          animation: slideUp 1s ease;
        }

        .feature-card {
          background: ${isDark ? 'rgba(30, 41, 59, 0.6)' : 'rgba(255, 255, 255, 0.6)'};
          backdrop-filter: blur(20px);
          border: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(255, 255, 255, 0.8)'};
          padding: 32px;
          border-radius: 24px;
          text-align: left;
          box-shadow: 0 10px 30px -5px rgba(0,0,0,0.02);
          transition: transform 0.3s ease;
        }

        .feature-card:hover {
          transform: translateY(-5px);
        }

        .feature-icon {
          width: 48px;
          height: 48px;
          background: ${isDark ? 'rgba(59, 130, 246, 0.2)' : '#eff6ff'};
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: ${isDark ? '#60a5fa' : '#2563eb'};
          margin-bottom: 20px;
        }

        .feature-title {
          font-size: 20px;
          font-weight: 700;
          margin-bottom: 12px;
          color: inherit;
          letter-spacing: -0.5px;
        }

        .feature-desc {
          font-size: 14px;
          color: ${isDark ? '#94a3b8' : '#64748b'};
          line-height: 1.6;
        }

        @keyframes slideUp {
          from { opacity: 0; transform: translateY(30px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-20px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <nav className="navbar">
        <div className="brand">
          <div className="brand-icon-wrap">
            <Shield size={24} color="white" strokeWidth={2} />
          </div>
          NIDS Project
        </div>
        <div className="nav-actions">
          <button className="theme-btn" onClick={toggleTheme}>
            {isDark ? <Sun size={20} /> : <Moon size={20} />}
          </button>
          <button className="nav-btn" onClick={onEnter}>Sign In</button>
        </div>
      </nav>

      <div className="hero-section">
        <div className="pill-badge">
          <Activity size={14} /> V1.0 Live Analysis Active
        </div>

        <h1 className="hero-title">
          Next-Generation <br />
          <span>Network Security</span>
        </h1>

        <p className="hero-desc">
          An AI-powered intrusion detection system using GAN-augmented XGBoost to monitor, analyze, and neutralize network threats in real-time.
        </p>

        <button className="cta-btn" onClick={onEnter}>
          Access Command Center <ArrowRight size={20} />
        </button>
      </div>

      <div className="features-grid">
        <div className="feature-card">
          <div className="feature-icon">
            <BrainCircuit size={24} />
          </div>
          <h3 className="feature-title">AI-Powered Detection</h3>
          <p className="feature-desc">
            Utilizes a highly optimized XGBoost classifier trained on extensive datasets to achieve over 99% accuracy across various intrusion tactics including DDoS, Web Attacks, and Infiltrations.
          </p>
        </div>

        <div className="feature-card">
          <div className="feature-icon">
            <Activity size={24} />
          </div>
          <h3 className="feature-title">Real-time Sniffing</h3>
          <p className="feature-desc">
            Directly interfaces with network traffic on your infrastructure. Extracts flow telemetry and applies instant machine learning inferences to block threats at the wire speed.
          </p>
        </div>

        <div className="feature-card">
          <div className="feature-icon">
            <Lock size={24} />
          </div>
          <h3 className="feature-title">GAN Augmentation</h3>
          <p className="feature-desc">
            Uses Generative Adversarial Networks to synthetically augment minority attack classes, preventing the classifier from developing severe biases during training.
          </p>
        </div>
      </div>
    </div>
  );
}
