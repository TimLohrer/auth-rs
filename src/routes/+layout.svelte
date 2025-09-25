<script lang="ts">
	import { apiUrl } from '$lib/store/config';
	import { onMount, onDestroy } from 'svelte';
	import { initializeJsonClickHandler, cleanupJsonClickHandler } from '$lib/utils/jsonClickHandler';
	import GlobalJsonViewPopup from '$lib/components/global/GlobalJsonViewPopup.svelte';
	import '../app.css';
	
	let { data, children } = $props<{
		data: { apiUrl: string };
		children: any;
	}>();

	apiUrl.set(data.apiUrl);

	onMount(() => {
		initializeJsonClickHandler();
	});

	onDestroy(() => {
		cleanupJsonClickHandler();
	});
</script>

{@render children()}

<!-- Global JSON View Popup -->
<GlobalJsonViewPopup />
