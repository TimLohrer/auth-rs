/**
 * Creates attributes for adding JSON data to HTML elements
 * 
 * @param data - The JSON data to attach to the element
 * @param title - Optional title for the JSON popup
 * @returns Object with data-json and optionally data-json-title attributes
 * 
 * @example
 * ```svelte
 * <div {...jsonAttributes(user, "User Data")}>
 *   Ctrl+click me to view user JSON
 * </div>
 * ```
 * 
 * @example
 * ```svelte
 * <button {...jsonAttributes({ id: 1, name: "Test" })}>
 *   Debug Button (Ctrl+click)
 * </button>
 * ```
 */
export function jsonAttributes(data: any, title?: string): { [key: string]: string } {
	const attributes: { [key: string]: string } = {
		'data-json': JSON.stringify(data)
	};

	if (title) {
		attributes['data-json-title'] = title;
	}

	return attributes;
}

/**
 * Action for use with Svelte's use: directive
 * 
 * @param node - The DOM element
 * @param params - Object with data and optional title
 * 
 * @example
 * ```svelte
 * <div use:jsonAction={{ data: user, title: "User Data" }}>
 *   Ctrl+click me to view user JSON
 * </div>
 * ```
 */
export function jsonAction(
	node: HTMLElement, 
	params: { data: any; title?: string }
) {
	function updateAttributes() {
		node.setAttribute('data-json', JSON.stringify(params.data));
		if (params.title) {
			node.setAttribute('data-json-title', params.title);
		} else {
			node.removeAttribute('data-json-title');
		}
	}

	updateAttributes();

	return {
		update(newParams: { data: any; title?: string }) {
			params = newParams;
			updateAttributes();
		},
		destroy() {
			node.removeAttribute('data-json');
			node.removeAttribute('data-json-title');
		}
	};
}