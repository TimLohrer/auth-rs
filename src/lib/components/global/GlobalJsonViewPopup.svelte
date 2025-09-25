<script lang="ts">
	import Popup from '$lib/components/global/Popup.svelte';
	import { jsonPopupState, closeJsonPopup } from '$lib/store/jsonPopup';
	import { debugMode } from '$lib/store/config';
    import { JsonView } from "@zerodevx/svelte-json-view";
</script>

{#if $jsonPopupState.isOpen && $debugMode}
    <div class="fixed w-full h-full flex flex-col items-center justify-center top-0 left-0 z-[1000] bg-black bg-opacity-50">
        <Popup title={$jsonPopupState.title || "JSON View"} onClose={closeJsonPopup}>
            <div class="flex flex-col min-w-[350px] max-w-[80vw] max-h-[80vh] overflow-auto">
                <JsonView json={$jsonPopupState.data} />
            </div>
        </Popup>
    </div>
{/if}