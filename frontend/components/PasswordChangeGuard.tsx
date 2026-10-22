"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";

/**
 * An admin created the account or reset the password: until the user has chosen
 * their own password, every page leads to the profile page (the server refuses
 * everything else anyway, see "Password change required").
 */
export function PasswordChangeGuard() {
  const { user } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (user?.must_change_password && pathname !== "/profile") {
      router.replace("/profile");
    }
  }, [user, pathname, router]);

  return null;
}
