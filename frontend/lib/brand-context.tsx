"use client";

import { createContext, useContext } from "react";
import { DEFAULT_BRAND, type Brand } from "./brand";

const BrandContext = createContext<Brand>(DEFAULT_BRAND);

export function BrandProvider({ brand, children }: { brand: Brand; children: React.ReactNode }) {
  return <BrandContext.Provider value={brand}>{children}</BrandContext.Provider>;
}

/** Name, logos and texts of this instance (default: InterCat Lynx). */
export function useBrand(): Brand {
  return useContext(BrandContext);
}
