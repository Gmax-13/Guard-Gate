'use client';

import { useEffect, useState } from 'react';
import { Sun, Moon } from 'lucide-react';

export default function ThemeToggle() {
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const activeTheme = (document.documentElement.getAttribute('data-theme') as 'light' | 'dark') || 'light';
    setTheme(activeTheme);
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('theme', nextTheme);
  };

  if (!mounted) {
    return <div style={{ width: '40px', height: '40px' }} />;
  }

  return (
    <button
      onClick={toggleTheme}
      style={{
        background: 'none',
        border: '1px solid var(--border)',
        borderRadius: '50%',
        width: '40px',
        height: '40px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--text-primary)',
        transition: 'background-color 0.2s, border-color 0.2s',
      }}
      aria-label="Toggle theme"
      className="hover-scale"
    >
      {theme === 'light' ? <Moon size={20} /> : <Sun size={20} />}
    </button>
  );
}
