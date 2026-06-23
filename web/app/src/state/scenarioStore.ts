import { create } from "zustand";

interface ScenarioState {
  domainId: string;
  setDomain: (id: string) => void;
}

export const useScenarioStore = create<ScenarioState>((set) => ({
  domainId: "manufacturing",
  setDomain: (id) => set({ domainId: id }),
}));
