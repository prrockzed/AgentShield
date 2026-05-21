import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  accessToken:  string | null
  refreshToken: string | null
  email:        string | null
  setTokens:   (access: string, refresh: string, email: string) => void
  clearTokens: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      accessToken: null, refreshToken: null, email: null,
      setTokens:  (accessToken, refreshToken, email) =>
        set({ accessToken, refreshToken, email }),
      clearTokens: () => set({ accessToken: null, refreshToken: null, email: null }),
    }),
    { name: 'auth-store' }
  )
)
