import React, { useState, useEffect } from 'react';
import Home from './components/Home';
import Login from './components/Login';
import Landing from './components/Landing';

function App() {
  const [showLanding, setShowLanding] = useState(true);
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('nids_theme') || 'light';
  });
  
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('nids_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    localStorage.setItem('nids_theme', theme);
    if (theme === 'light') {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
  }, [theme]);

  const handleLogin = (userProfile) => {
    setUser(userProfile);
    localStorage.setItem('nids_user', JSON.stringify(userProfile));
  };

  const handleLogout = () => {
    setUser(null);
    setShowLanding(true); // Go back to landing on logout
    localStorage.removeItem('nids_user');
  };

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  return (
    <div className="App">
      {user ? (
        <Home user={user} onLogout={handleLogout} theme={theme} toggleTheme={toggleTheme} />
      ) : showLanding ? (
        <Landing onEnter={() => setShowLanding(false)} theme={theme} toggleTheme={toggleTheme} />
      ) : (
        <Login onLogin={handleLogin} theme={theme} toggleTheme={toggleTheme} />
      )}
    </div>
  );
}

export default App;
