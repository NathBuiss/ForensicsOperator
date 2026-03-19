/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Light-mode gray scale (body bg, cards, borders)
        gray: {
          50:  '#F8F9FC',
          100: '#F1F3F7',
          200: '#E2E8F0',
          300: '#CBD5E1',
          400: '#94A3B8',
          500: '#6B7280',
          600: '#4B5563',
          700: '#374151',
          800: '#1F2937',
          900: '#111827',
          950: '#0a0a0f',  // kept for code blocks / monospace areas
        },
        // Brand tokens — sidebar navy + Kibana-style blue accent
        brand: {
          sidebar:     '#1B1C31',
          sidebarmuted:'#A8ABBE',
          accent:      '#0077CC',
          accenthover: '#005FA3',
          accentlight: '#E6F2FB',
          text:        '#1C1E2E',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 3px 0 rgba(0,0,0,0.08), 0 1px 2px -1px rgba(0,0,0,0.04)',
        'card-md': '0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -2px rgba(0,0,0,0.04)',
      },
    },
  },
  plugins: [],
}
