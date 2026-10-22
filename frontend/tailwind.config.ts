import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Intercat Corporate Design (see Intercat Styleguide). The default Tailwind
        // gray and blue scales are replaced, so every existing utility class
        // (bg-gray-800, text-blue-400, ...) picks up the brand colours.
        gray: {
          50: "#f7f8f9",
          100: "#eef0f2",
          200: "#dde1e5",
          300: "#d5dadf", // body text on dark (Fliesstext)
          400: "#9aa3ad",
          500: "#6b7580",
          600: "#4a525b",
          700: "#2a2d31", // line (Linie)
          800: "#1c1e21", // surface (Flaeche)
          900: "#131416", // background (Hintergrund)
          950: "#0d0e10",
        },
        blue: {
          50: "#eef6fc",
          100: "#dcecf8",
          200: "#b9d9f1",
          300: "#a6dbff",
          400: "#7fcbff", // accent (Akzentblau)
          500: "#2b7fc4",
          600: "#2271b3", // brand blue (Markenblau, RAL 5015)
          700: "#1d62a0", // brand blue dark
          800: "#184e80",
          900: "#14293a",
        },
        brand: {
          DEFAULT: "#2271b3",
          dark: "#1d62a0",
          accent: "#7fcbff",
          "accent-dark": "#5cbefe",
        },
        surface: {
          DEFAULT: "#1c1e21",
          2: "#26292d",
        },
        link: "hsl(var(--link))",
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
      },
      borderRadius: {
        // Styleguide: tiles 16 px, icon fields 12 px, buttons 8 px
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [],
};

export default config;
