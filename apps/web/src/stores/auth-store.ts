'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
    id: string;
    email: string;
    name: string;
    organizationId?: string;
    roles: string[];
}

interface AuthState {
    user: User | null;
    accessToken: string | null;
    refreshToken: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
    requiresMfa: boolean;
    mfaToken: string | null;

    // Actions
    setUser: (user: User | null) => void;
    setTokens: (accessToken: string, refreshToken: string) => void;
    setMfaRequired: (mfaToken: string) => void;
    setError: (error: string | null) => void;
    setLoading: (isLoading: boolean) => void;
    logout: () => void;
    clearMfa: () => void;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set) => ({
            user: null,
            accessToken: null,
            refreshToken: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
            requiresMfa: false,
            mfaToken: null,

            setUser: (user) =>
                set({
                    user,
                    isAuthenticated: !!user,
                }),

            setTokens: (accessToken, refreshToken) =>
                set({
                    accessToken,
                    refreshToken,
                    requiresMfa: false,
                    mfaToken: null,
                }),

            setMfaRequired: (mfaToken) =>
                set({
                    requiresMfa: true,
                    mfaToken,
                }),

            setError: (error) => set({ error }),

            setLoading: (isLoading) => set({ isLoading }),

            logout: () =>
                set({
                    user: null,
                    accessToken: null,
                    refreshToken: null,
                    isAuthenticated: false,
                    requiresMfa: false,
                    mfaToken: null,
                    error: null,
                }),

            clearMfa: () =>
                set({
                    requiresMfa: false,
                    mfaToken: null,
                }),
        }),
        {
            name: 'auth-storage',
            partialize: (state) => ({
                user: state.user,
                accessToken: state.accessToken,
                refreshToken: state.refreshToken,
                isAuthenticated: state.isAuthenticated,
            }),
        }
    )
);
