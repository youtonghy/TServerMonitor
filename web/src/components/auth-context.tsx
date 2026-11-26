import { createContext, useContext } from "react";
import type { AuthUser } from "@/api/types";

export interface AuthInfo {
  user: AuthUser | null;
  logout: () => void;
}

export const AuthContext = createContext<AuthInfo>({ user: null, logout: () => {} });

export function useAuth(): AuthInfo {
  return useContext(AuthContext);
}
