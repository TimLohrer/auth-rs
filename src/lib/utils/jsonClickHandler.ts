import { openJsonPopup } from '$lib/store/jsonPopup';
import { get } from 'svelte/store';
import { debugMode } from '$lib/store/config';

const JSON_ATTRIBUTE = 'data-json';
const JSON_TITLE_ATTRIBUTE = 'data-json-title';

export function initializeJsonClickHandler() {
	if (typeof window !== 'undefined' && !window.__jsonClickHandlerInitialized) {
		window.__jsonClickHandlerInitialized = true;
		
		document.addEventListener('click', handleJsonClick, true);
	}
}

export function cleanupJsonClickHandler() {
	if (typeof window !== 'undefined') {
		document.removeEventListener('click', handleJsonClick, true);
		window.__jsonClickHandlerInitialized = false;
	}
}

function handleJsonClick(event: Event) {
	if (!get(debugMode)) {
		return;
	}

	const target = event.target as HTMLElement;
	if (!target) return;

	const jsonElement = target.closest(`[${JSON_ATTRIBUTE}]`) as HTMLElement;
	if (!jsonElement) return;

    const keyEvent = event as MouseEvent;
    if (!keyEvent.ctrlKey && !keyEvent.metaKey) return;

	event.preventDefault();
	event.stopPropagation();

	const jsonString = jsonElement.getAttribute(JSON_ATTRIBUTE);
	const title = jsonElement.getAttribute(JSON_TITLE_ATTRIBUTE) || 'JSON Data';

	if (!jsonString) return;

	try {
		const jsonData = JSON.parse(jsonString);
		openJsonPopup(jsonData, title);
	} catch (error) {
		console.error('Failed to parse JSON from data-json attribute:', error);
		openJsonPopup({ error: 'Invalid JSON', raw: jsonString }, title);
	}
}

declare global {
	interface Window {
		__jsonClickHandlerInitialized?: boolean;
	}
}