/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./layouts/**/*.html",
    "./content/**/*.{html,md}",
    "./assets/**/*.js",
    "./assets/scss/**/*.scss",
  ],
  // Minimal safelist - only for DevTools testing and CMS content
  // Most classes are auto-detected from templates by Tailwind JIT
  safelist: [
    // DevTools testing - common utilities your content team might use via CMS
    { pattern: /^(w|h)-(full|auto|1\/2|1\/3|2\/3|1\/4|3\/4)$/ },
    { pattern: /^(sm|md|lg|xl):w-(full|1\/2|1\/3|1\/4)$/ },
    { pattern: /^(p|m|py|px|my|mx|pt|pb|mt|mb)-[0-8]$/ },
    { pattern: /^(md|lg):(py|px|p|m|mt|mb)-[0-8]$/ },
    { pattern: /^gap-[0-6]$/ },
    { pattern: /^text-(xs|sm|base|lg|xl|2xl|3xl)$/ },
    { pattern: /^font-(normal|medium|semibold|bold)$/ },
    { pattern: /^(hidden|block|flex|grid)$/ },
    { pattern: /^(md|lg):(hidden|block|flex)$/ },
    { pattern: /^text-(left|center|right)$/ },
    { pattern: /^(md|lg):text-(left|center|right)$/ },
    // Colors commonly used in CMS content
    { pattern: /^bg-(gray|red|green|blue|emerald|purple)-(500|600|700|800)$/ },
    { pattern: /^text-gray-(300|400|500|600|700)$/ },
    'bg-white', 'bg-black', 'bg-transparent',
    'text-white', 'text-black',
    // Focus states for accessibility
    'focus:outline-none', 'focus:ring-2', 'focus:ring-white', 'focus:ring-offset-2',
  ],
  theme: {
    extend: {
      // Bootstrap color names mapped to values
      colors: {
        'primary': '#F7931A',
        'secondary': '#6c757d',
        'success': '#198754',
        'danger': '#dc3545',
        'warning': '#ffc107',
        'info': '#0dcaf0',
        'light': '#f8f9fa',
        'dark': '#212529',
      },
      fontFamily: {
        'sans': ['Lato', 'sans-serif'],
        'roboto': ['Roboto', 'sans-serif'],
      },
      maxWidth: {
        '1340': '1340px',
      },
    },
    // Bootstrap breakpoints
    screens: {
      'sm': '576px',
      'md': '768px',
      'lg': '992px',
      'xl': '1200px',
      'xxl': '1400px',
    },
  },
  plugins: [],
}
