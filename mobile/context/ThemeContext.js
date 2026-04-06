// PATH: vulnassess-app/context/ThemeContext.js
import React, { createContext, useContext, useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

const ThemeContext = createContext();

export const lightTheme = {
  dark: false,
  bg:             '#ECEFF1',
  bg2:            '#E4E8EB',
  card:           '#FDFFF5',
  header:         '#191970',
  headerText:     '#FDFFF5',
  sidebar:        '#191970',
  text:           '#2C2C2A',
  textSecondary:  '#5F5E5A',
  textMuted:      '#888780',
  border:         '#D3D1C7',
  input:          '#FDFFF5',
  inputBorder:    '#D3D1C7',
  accent:         '#191970',
  accentMuted:    'rgba(25,25,112,0.08)',
  // Severity
  critical:       '#A32D2D',
  criticalBg:     '#FCEBEB',
  criticalBorder: '#F7C1C1',
  high:           '#854F0B',
  highBg:         '#FAEEDA',
  highBorder:     '#FAC775',
  medium:         '#185FA5',
  mediumBg:       '#E6F1FB',
  mediumBorder:   '#B5D4F4',
  low:            '#3B6D11',
  lowBg:          '#EAF3DE',
  lowBorder:      '#C0DD97',
  // Status
  success:        '#3B6D11',
  successBg:      '#EAF3DE',
  successBorder:  '#C0DD97',
  warning:        '#BA7517',
  warningBg:      '#FAEEDA',
  danger:         '#A32D2D',
  dangerBg:       '#FCEBEB',
  dangerBorder:   '#F7C1C1',
  blue:           '#185FA5',
  blueBg:         '#E6F1FB',
  blueBorder:     '#B5D4F4',
  muted:          '#888780',
  // Legacy
  statCard:       '#FDFFF5',
  scanCard:       '#FDFFF5',
  pill:           '#FDFFF5',
  pillBorder:     '#D3D1C7',
  shadow:         '#000',
};

export const darkTheme = {
  dark: true,
  bg:             '#060a0f',
  bg2:            '#0d1117',
  card:           '#111827',
  header:         '#191970',
  headerText:     '#FDFFF5',
  sidebar:        '#191970',
  text:           '#e2e8f0',
  textSecondary:  '#94a3b8',
  textMuted:      '#64748b',
  border:         '#1e2d3d',
  input:          '#0d1117',
  inputBorder:    '#1e2d3d',
  accent:         '#00d4ff',
  accentMuted:    'rgba(0,212,255,0.08)',
  // Severity
  critical:       '#F7C1C1',
  criticalBg:     '#791F1F',
  criticalBorder: '#A32D2D',
  high:           '#FAC775',
  highBg:         '#633806',
  highBorder:     '#854F0B',
  medium:         '#B5D4F4',
  mediumBg:       '#0C447C',
  mediumBorder:   '#185FA5',
  low:            '#C0DD97',
  lowBg:          '#27500A',
  lowBorder:      '#3B6D11',
  // Status
  success:        '#00ff88',
  successBg:      '#052E16',
  successBorder:  '#14532D',
  warning:        '#FAC775',
  warningBg:      '#633806',
  danger:         '#F87171',
  dangerBg:       '#450A0A',
  dangerBorder:   '#7F1D1D',
  blue:           '#85B7EB',
  blueBg:         '#172554',
  blueBorder:     '#1E3A8A',
  muted:          '#64748b',
  // Legacy
  statCard:       '#111827',
  scanCard:       '#111827',
  pill:           '#111827',
  pillBorder:     '#1e2d3d',
  shadow:         '#000',
};

export function ThemeProvider({ children }) {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => { loadTheme(); }, []);

  const loadTheme = async () => {
    const saved = await AsyncStorage.getItem('theme');
    if (saved === 'dark') setIsDark(true);
  };

  const toggleTheme = async () => {
    const newVal = !isDark;
    setIsDark(newVal);
    await AsyncStorage.setItem('theme', newVal ? 'dark' : 'light');
  };

  return (
    <ThemeContext.Provider value={{ theme: isDark ? darkTheme : lightTheme, isDark, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);