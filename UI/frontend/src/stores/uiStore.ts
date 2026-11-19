import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UIState {
  sidebarCollapsed: boolean;
  mobileNavOpen: boolean;
  theme: 'light' | 'dark';
  activeModal: string | null;
  setSidebar: (collapsed: boolean) => void;
  setMobileNav: (open: boolean) => void;
  setTheme: (theme: 'light' | 'dark') => void;
  openModal: (id: string) => void;
  closeModal: () => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      mobileNavOpen: false,
      theme: 'light',
      activeModal: null,

      setSidebar: (collapsed) => set({ sidebarCollapsed: collapsed }),
      setMobileNav: (open) => set({ mobileNavOpen: open }),

      setTheme: (theme) => {
        document.documentElement.classList.toggle('dark', theme === 'dark');
        set({ theme });
      },

      openModal: (id) => set({ activeModal: id }),
      closeModal: () => set({ activeModal: null }),
    }),
    {
      name: 'attacksentry-ui',
      version: 2,
      // Earlier builds defaulted to dark. Reset the stored preference once so
      // existing browsers pick up the light default; the toggle still works.
      migrate: (persisted: any, version) => ({
        ...persisted,
        ...(version < 2 ? { theme: 'light' } : {}),
      }),
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
      onRehydrateStorage: () => (state) => {
        const theme = state?.theme ?? 'light';
        document.documentElement.classList.toggle('dark', theme === 'dark');
      },
    }
  )
);
