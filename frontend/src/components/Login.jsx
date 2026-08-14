import React, { useState } from 'react';
import { Shield, Eye, EyeOff, Moon, Sun, ArrowLeft } from 'lucide-react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

export default function Login({ onLogin, theme, toggleTheme }) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [isVerifyingCode, setIsVerifyingCode] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [contact, setContact] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const isDark = theme === 'dark';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if ((isRegistering || isResetting) && password.length > 0) {
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%]).{8,}$/;
      if (!passwordRegex.test(password)) {
        setError('Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character (!@#$%).');
        return;
      }
    }

    if (isRegistering || isResetting) {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(email)) {
        setError('Please enter a valid email address in a proper format (e.g., user@gmail.com).');
        return;
      }
    }

    if (isRegistering) {
      if (!/^[a-zA-Z0-9._]+$/.test(username)) {
        setError('Username can only contain letters, numbers, dots, and underscores.');
        return;
      }
      if (/[._]{2,}/.test(username)) {
        setError('Username cannot contain consecutive dots or underscores.');
        return;
      }
      if (username.toLowerCase() === password.toLowerCase()) {
        setError('Password cannot be identical to your username.');
        return;
      }
    }

    if (isResetting) {
      if (!email || !password) {
        setError('Email and new password are required.');
        return;
      }
    }

    setLoading(true);

    if ((isRegistering || isResetting) && !isVerifyingCode) {
      try {
        const response = await fetch(`${BACKEND_URL}/api/send-code`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: isRegistering ? 'register' : 'reset',
            email: email,
            username: isRegistering ? username : undefined
          }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Failed to send verification code');

        setIsVerifyingCode(true);
        setError('');
        alert('A 4-digit verification code has been sent to your email.');
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
      return;
    }

    let endpoint = `${BACKEND_URL}/api/login`;
    let payload = { username, password };

    if (isRegistering) {
      endpoint = `${BACKEND_URL}/api/register`;
      payload = { username, password, firstName, lastName, email, contact, code: verificationCode.replace(/ /g, '') };
    } else if (isResetting) {
      endpoint = `${BACKEND_URL}/api/reset-password`;
      payload = { email, newPassword: password, code: verificationCode.replace(/ /g, '') };
    }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      if (isRegistering) {
        setIsRegistering(false);
        setIsVerifyingCode(false);
        setVerificationCode('');
        setError('');
        alert('Registration successful! Please login with your new credentials.');
      } else if (isResetting) {
        setIsResetting(false);
        setIsVerifyingCode(false);
        setVerificationCode('');
        setPassword('');
        setError('');
        alert('Password reset successful! Please login.');
      } else {
        onLogin(data.user);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCodeChange = (index, value) => {
    if (value.length > 1) {
      const pasted = value.replace(/\D/g, '').slice(0, 4).padEnd(4, ' ');
      setVerificationCode(pasted);
      const lastIndex = pasted.trim().length - 1;
      document.getElementById(`code-input-${Math.max(0, Math.min(3, lastIndex))}`)?.focus();
      return;
    }
    if (!/^\d*$/.test(value)) return;
    const chars = (verificationCode || '').padEnd(4, ' ').split('');
    chars[index] = value || ' ';
    setVerificationCode(chars.join(''));
    if (value && index < 3) {
      document.getElementById(`code-input-${index + 1}`)?.focus();
    }
  };

  const handleCodeKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !e.target.value && index > 0) {
      document.getElementById(`code-input-${index - 1}`)?.focus();
    }
  };

  return (
    <div className="login-root">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');

        .login-root {
          font-family: 'Outfit', sans-serif;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: ${isDark ? '#0f172a' : '#f8fafc'};
          position: relative;
          overflow: hidden;
          transition: background 0.3s ease;
        }

        .login-root::before, .login-root::after {
          content: '';
          position: absolute;
          border-radius: 50%;
          filter: blur(80px);
          z-index: 0;
          animation: float 10s ease-in-out infinite alternate;
        }
        
        .login-root::before {
          width: 600px;
          height: 600px;
          background: rgba(56, 189, 248, 0.15);
          top: -100px;
          left: -100px;
        }
        
        .login-root::after {
          width: 500px;
          height: 500px;
          background: rgba(167, 139, 250, 0.15);
          bottom: -50px;
          right: -100px;
          animation-delay: -5s;
        }

        @keyframes float {
          0% { transform: translate(0, 0) scale(1); }
          100% { transform: translate(30px, 50px) scale(1.1); }
        }

        .auth-container {
          position: relative;
          z-index: 10;
          width: 100%;
          max-width: 440px;
          padding: 20px;
        }

        .auth-card {
          background: ${isDark ? 'rgba(30, 41, 59, 0.6)' : 'rgba(255, 255, 255, 0.6)'};
          backdrop-filter: blur(24px);
          -webkit-backdrop-filter: blur(24px);
          border: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(255, 255, 255, 0.8)'};
          border-radius: 24px;
          padding: 48px 40px;
          box-shadow: 0 20px 40px -10px rgba(0,0,0,0.05);
          animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes slideUp {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .brand-header {
          display: flex;
          flex-direction: column;
          align-items: center;
          margin-bottom: 32px;
          text-align: center;
        }

        .brand-icon-wrap {
          width: 64px;
          height: 64px;
          background: linear-gradient(135deg, #38bdf8 0%, #2563eb 100%);
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 16px;
          box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);
        }

        .card-title {
          font-size: 28px;
          font-weight: 700;
          color: ${isDark ? '#f8fafc' : '#0f172a'};
          margin-bottom: 6px;
          letter-spacing: -0.5px;
        }

        .card-sub {
          font-size: 14px;
          color: ${isDark ? '#94a3b8' : '#64748b'};
          font-weight: 400;
        }

        .input-group {
          margin-bottom: 20px;
        }

        .input-label {
          display: block;
          font-size: 13px;
          font-weight: 500;
          color: ${isDark ? '#cbd5e1' : '#334155'};
          margin-bottom: 8px;
        }

        .input-wrapper {
          position: relative;
        }

        .input-field {
          width: 100%;
          background: ${isDark ? 'rgba(15, 23, 42, 0.6)' : 'rgba(255, 255, 255, 0.8)'};
          border: 1px solid ${isDark ? 'rgba(51, 65, 85, 0.8)' : 'rgba(226, 232, 240, 0.8)'};
          color: ${isDark ? '#f8fafc' : '#0f172a'};
          padding: 14px 16px;
          border-radius: 12px;
          font-family: inherit;
          font-size: 14px;
          transition: all 0.2s ease;
          outline: none;
          box-shadow: inset 0 2px 4px rgba(0,0,0,0.01);
        }

        .input-field:focus {
          border-color: #38bdf8;
          background: ${isDark ? '#0f172a' : '#ffffff'};
          box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.1), inset 0 2px 4px rgba(0,0,0,0.01);
        }
        
        .input-icon-right {
          position: absolute;
          right: 16px;
          top: 50%;
          transform: translateY(-50%);
          color: #94a3b8;
          cursor: pointer;
          transition: color 0.2s;
        }

        .input-icon-right:hover {
          color: ${isDark ? '#f8fafc' : '#0f172a'};
        }

        .actions-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 28px;
          font-size: 13px;
        }

        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 8px;
          color: ${isDark ? '#cbd5e1' : '#475569'};
          cursor: pointer;
          font-weight: 500;
        }

        .checkbox {
          accent-color: #2563eb;
          width: 16px;
          height: 16px;
          border-radius: 4px;
        }

        .forgot-link {
          color: #38bdf8;
          text-decoration: none;
          font-weight: 500;
        }
        .forgot-link:hover { text-decoration: underline; }

        .submit-btn {
          width: 100%;
          background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
          color: white;
          border: none;
          padding: 16px;
          border-radius: 12px;
          font-weight: 600;
          font-size: 15px;
          cursor: pointer;
          transition: all 0.2s;
          margin-bottom: 24px;
          box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2);
        }

        .submit-btn:hover {
          transform: translateY(-1px);
          box-shadow: 0 6px 16px rgba(37, 99, 235, 0.3);
        }
        .submit-btn:active {
          transform: translateY(1px);
          box-shadow: 0 2px 8px rgba(37, 99, 235, 0.2);
        }
        .submit-btn:disabled { 
          opacity: 0.7; 
          cursor: not-allowed; 
          transform: none;
        }

        .toggle-link {
          text-align: center;
          font-size: 14px;
          color: ${isDark ? '#94a3b8' : '#64748b'};
        }

        .toggle-link span {
          color: #38bdf8;
          cursor: pointer;
          font-weight: 600;
          margin-left: 6px;
        }
        .toggle-link span:hover { text-decoration: underline; }

        .error-msg {
          color: ${isDark ? '#f87171' : '#e11d48'};
          font-size: 13px;
          margin-bottom: 20px;
          background: ${isDark ? 'rgba(153, 27, 27, 0.2)' : 'rgba(255, 228, 230, 0.7)'};
          border: 1px solid ${isDark ? 'rgba(153, 27, 27, 0.5)' : 'rgba(254, 205, 211, 0.8)'};
          padding: 12px 16px;
          border-radius: 10px;
          font-weight: 500;
          backdrop-filter: blur(4px);
        }

        .code-inputs {
          display: flex;
          gap: 12px;
          justify-content: center;
          margin-top: 4px;
        }
        .code-input-box {
          width: 52px;
          height: 60px;
          border-radius: 12px;
          border: 1.5px solid ${isDark ? '#334155' : '#e2e8f0'};
          background: ${isDark ? 'rgba(255,255,255,0.03)' : '#fff'};
          color: ${isDark ? '#f8fafc' : '#0f172a'};
          font-size: 1.75rem;
          font-weight: 600;
          text-align: center;
          transition: all 0.2s;
        }
        .code-input-box:focus {
          outline: none;
          border-color: #2563eb;
          box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
        }

        .top-nav {
          position: absolute;
          top: 24px;
          right: 32px;
          z-index: 20;
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
      `}</style>

      <div className="top-nav">
        <button className="theme-btn" onClick={toggleTheme} title="Toggle Theme">
          {isDark ? <Sun size={20} /> : <Moon size={20} />}
        </button>
      </div>

      <div className="auth-container">
        <div className="auth-card">
          <div className="brand-header">
            <div className="brand-icon-wrap">
              <Shield size={32} color="white" strokeWidth={1.5} />
            </div>
            <div className="card-title">
              {isResetting ? "Reset Password" : (isRegistering ? "Create Account" : "Welcome Back")}
            </div>
            <div className="card-sub">
              {isResetting ? "Enter your email to reset your password" : (isRegistering ? "Join NIDS to secure your network" : "Sign in to continue to NIDS")}
            </div>
          </div>

          <form onSubmit={handleSubmit}>
            {error && <div className="error-msg">{error}</div>}

            {isVerifyingCode ? (
              <div className="input-group" style={{ textAlign: 'center' }}>
                <label className="input-label" style={{ textAlign: 'center', marginBottom: '8px' }}>4-Digit Verification Code</label>
                <div className="code-inputs">
                  {[0, 1, 2, 3].map(i => (
                    <input
                      key={i}
                      id={`code-input-${i}`}
                      type="text"
                      className="code-input-box"
                      value={(verificationCode || '').padEnd(4, ' ')[i] === ' ' ? '' : (verificationCode || '').padEnd(4, ' ')[i]}
                      onChange={(e) => handleCodeChange(i, e.target.value)}
                      onKeyDown={(e) => handleCodeKeyDown(i, e)}
                    />
                  ))}
                </div>
              </div>
            ) : (
              <>
                {isRegistering && !isResetting && (
                  <>
                    <div className="input-group">
                      <label className="input-label">First Name</label>
                      <input type="text" className="input-field" placeholder="John" value={firstName} onChange={(e) => setFirstName(e.target.value)} required />
                    </div>
                    <div className="input-group">
                      <label className="input-label">Last Name</label>
                      <input type="text" className="input-field" placeholder="Doe" value={lastName} onChange={(e) => setLastName(e.target.value)} required />
                    </div>
                  </>
                )}

                {(isRegistering || isResetting) && (
                  <div className="input-group">
                    <label className="input-label">Email</label>
                    <input type="email" className="input-field" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                  </div>
                )}

                {!isResetting && (
                  <div className="input-group">
                    <label className="input-label">Username</label>
                    <input type="text" className="input-field" placeholder="Enter your ID" value={username} onChange={(e) => setUsername(e.target.value)} required pattern="^(?!.*[._]{2})[a-zA-Z0-9._]+$" title="Only letters, numbers, dots, and underscores are allowed. Cannot have consecutive dots or underscores." />
                  </div>
                )}

                <div className="input-group">
                  <label className="input-label">{isResetting ? "New Password" : "Password"}</label>
                  <div className="input-wrapper">
                    <input type={showPassword ? "text" : "password"} className="input-field" placeholder={isResetting ? "Create a new password" : (isRegistering ? "Create a password" : "Enter your password")} value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
                    {password.length > 0 && (
                      <div className="input-icon-right" onClick={() => setShowPassword(!showPassword)}>
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </div>
                    )}
                  </div>
                </div>

                {!isRegistering && !isResetting && (
                  <div className="actions-row">
                    <label className="checkbox-label">
                      <input type="checkbox" className="checkbox" /> Remember me
                    </label>
                    <span className="forgot-link" style={{ cursor: 'pointer' }} onClick={() => { setIsResetting(true); setError(''); setIsVerifyingCode(false); }}>Forgot Password?</span>
                  </div>
                )}
              </>
            )}

            <button type="submit" className="submit-btn" disabled={loading || (!isVerifyingCode && password.length < 8)}>
              {loading ? 'Processing...' : (isVerifyingCode ? 'Verify & Submit' : (isResetting ? 'Send Reset Code' : (isRegistering ? 'Send Verification Code' : 'Login')))}
            </button>

            <div className="toggle-link">
              {isResetting ? (
                <>
                  Remember your password?
                  <span onClick={() => { setIsResetting(false); setError(''); setIsVerifyingCode(false); }}>Login</span>
                </>
              ) : (
                <>
                  {isRegistering ? "Already have an account?" : "Don't have an account?"}
                  <span onClick={() => { setIsRegistering(!isRegistering); setError(''); setIsVerifyingCode(false); }}>
                    {isRegistering ? "Login" : "Register"}
                  </span>
                </>
              )}
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
