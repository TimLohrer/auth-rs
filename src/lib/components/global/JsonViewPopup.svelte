<script lang="ts">
	import Popup from '$lib/components/global/Popup.svelte';
	import { debugMode } from '$lib/store/config';
    import { JsonView } from "@zerodevx/svelte-json-view";
	import { Eye } from 'lucide-svelte';

    export let data: any;

    let isOpen: boolean = false;
</script>

{#if $debugMode}
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div on:click={() => isOpen = true}>
        <Eye class="cursor-pointer text-blue-500" />
    </div>
{/if}

{#if isOpen && $debugMode}
    <div class="absolute w-full h-full flex flex-col items-center justify-center top-0 left-0 z-[1000]">
        <Popup title="JSON View" onClose={() => isOpen = false}>
            <div class="flex flex-col min-w-[350px]">
                <JsonView json={data} />
            </div>
        </Popup>
    </div>
{/if}