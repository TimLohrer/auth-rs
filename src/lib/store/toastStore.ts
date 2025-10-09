import type { Toast } from "$lib/models/Toast";
import { writable } from "svelte/store";

export const activeToasts = writable<Toast[]>([]);
export const toastQueue = writable<Toast[]>([]);

const markedToasts = new Set<string>();

toastQueue.subscribe((queuedToasts) => {
    if (queuedToasts.length > 0) {
        activeToasts.update((currentToasts) => {
            const spaceLeft = 3 - currentToasts.length;
            if (spaceLeft > 0) {
                const toAdd = queuedToasts.slice(0, spaceLeft);
                toastQueue.update((q) => q.slice(toAdd.length));
                setTimeout(() => toastQueue.update((q) => q.slice(toAdd.length)), toAdd.sort((a, b) => a.ttl - b.ttl)[0].ttl);
                return [...currentToasts, ...toAdd];
            }
            return currentToasts;
        });
    }
});

activeToasts.subscribe((toasts) => {
    console.log(`Active toasts: ${toasts.length}`);
    
    toasts.forEach((toast) => {
        if (!markedToasts.has(toast.id)) {
            markedToasts.add(toast.id);
            setTimeout(() => {
                activeToasts.update((currentToasts) =>
                    currentToasts.filter((t) => t.id !== toast.id)
                );
                markedToasts.delete(toast.id);
            }, toast.ttl);
        }
    });
});

export function showToast(toast: Toast) {
    toastQueue.update((toasts) => [...toasts, toast]);
}