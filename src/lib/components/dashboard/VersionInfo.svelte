<script lang="ts">
	import { onMount } from 'svelte';
	import { version, latestVersion, updateAvailable, updateCheckLoading, updateCheckError, checkForUpdates } from '$lib/store/version';
	import { ExternalLink, Download } from 'lucide-svelte';
	import User from '$lib/models/User';
	import { apiUrl, debugMode } from '$lib/store/config';
	import { get } from 'svelte/store';
	import AuthRsApi from '$lib/api';
	import { showToast } from '$lib/store/toastStore';
	import { Toast } from '$lib/models/Toast';

	export let user: User;

	let backendVersion: string | null | undefined = undefined;

	function toggleDebugMode() {
		if (User.isAdmin(user)) {
			debugMode.set(!get(debugMode));
		}
	}

	onMount(async () => {
		checkForUpdates();
		backendVersion = await (new AuthRsApi($apiUrl)).checkOnlineState();
		if (backendVersion !== undefined && backendVersion !== null && backendVersion !== $version && $version !== 'dev') {
			console.warn(`Version mismatch: Frontend version is ${$version}, but backend version is ${backendVersion}`);
			showToast(new Toast('Frontend and backend version mismatch! Please contact your system admin.', 'error'));
		}
	});
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="flex flex-col items-center gap-1 cursor-pointer" on:click={toggleDebugMode}>
	<div class="text-[11px] text-gray-400 opacity-70">
		<p class:text-blue-500={$debugMode}>{$version}</p>
	</div>
	
	{#if $updateCheckLoading || backendVersion === undefined}
		<div class="text-[9px] text-gray-500 opacity-60">
			Checking for updates...
		</div>
	{:else if $updateAvailable && $latestVersion}
		<a 
			href="https://github.com/TimLohrer/auth-rs/releases/latest"
			target="_blank"
			rel="noopener noreferrer"
			class="flex items-center gap-1 text-[9px] text-blue-400 hover:text-blue-300 transition-colors cursor-pointer"
			title="New version available: {$latestVersion}"
		>
			<Download size={8} />
			Update to {$latestVersion}
			<ExternalLink size={6} />
		</a>
	{:else if $updateCheckError}
		<div class="text-[9px] text-red-400 opacity-60" title="Error: {$updateCheckError}">
			Update check failed
		</div>
	{/if}
	{#if backendVersion !== $version && backendVersion !== undefined}
		<div class="text-[9px] text-yellow-400 opacity-70" title="Backend version: {backendVersion}">
			⚠️ Backend version mismatch: {backendVersion}
		</div>
	{/if}

</div>
