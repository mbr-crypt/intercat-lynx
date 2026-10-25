/** Branding of the instance as the pages use it (shared by server and browser code). */

import { PRODUCT_NAME } from "./branding";

export interface Brand {
  name: string;
  accent: string | null;
  footer_text: string | null;
  url: string | null;
  logo_light: string | null;
  logo_dark: string | null;
  /** Anything changed from the default look */
  custom: boolean;
}

export const DEFAULT_BRAND: Brand = {
  name: PRODUCT_NAME,
  accent: null,
  footer_text: null,
  url: null,
  logo_light: null,
  logo_dark: null,
  custom: false,
};
