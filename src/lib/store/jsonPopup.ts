import { writable } from 'svelte/store';

interface JsonPopupState {
	isOpen: boolean;
	data: any;
	title?: string;
}

export const jsonPopupState = writable<JsonPopupState>({
	isOpen: false,
	data: null,
	title: undefined
});

export function openJsonPopup(data: any, title?: string) {
	jsonPopupState.set({
		isOpen: true,
		data,
		title
	});
}

export function closeJsonPopup() {
	jsonPopupState.update(state => ({
		...state,
		isOpen: false
	}));
}