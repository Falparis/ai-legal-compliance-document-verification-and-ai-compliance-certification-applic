import { useActor as useCoreActor } from "@caffeineai/core-infrastructure";
import type { createActorFunction } from "@caffeineai/core-infrastructure";
import { createActor } from "../backend";
import type { ActorInterface } from "../types";

// Wrapper hook that binds the generated backend actor to the core infrastructure hook
export function useActor(): {
  actor: ActorInterface | null;
  isFetching: boolean;
} {
  return useCoreActor<ActorInterface>(
    createActor as unknown as createActorFunction<ActorInterface>,
  );
}
