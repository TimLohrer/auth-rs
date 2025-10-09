<script lang="ts">
	import { PlusCircle, X } from "lucide-svelte";
	import Tooltip from "sv-tooltip";

    export let redirectUris: string[];
    export let onAdd: () => void;
    export let onRemove: (role: string) => void;
</script>

<div class="flex flex-col">
    <div class="flex flex-row items-center gap-[5px]">
        <p class="text-[14px]" style="padding: 2px;">Redirect URI's</p>
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <Tooltip tip="Add Redirect URI" right>
            <div on:click={onAdd}>
                <PlusCircle size="15" class="hover:text-green-500 cursor-pointer transition-all" />
            </div>
        </Tooltip>
    </div>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="name-input flex flex-col items-start gap-[10px]">
        {#if redirectUris.length === 0}
            <p class="text-[13px] opacity-50" style="margin-top: 5px;"><i>No redirect URI's added</i></p>
        {/if}
        {#each redirectUris as redirectUri}
            <div class="flex flex-row items-center justify-between gap-[10px] text-[13px] bg-[#111] rounded-md" style="padding: 7.5px;">
                <p style="color: white !important;" class="wrap-anywhere break-all">{redirectUri.split('?')[0]}</p>
                <Tooltip tip="Remove Redirect URI" right color="var(--color-red-600)">
                    <div on:click={() => onRemove(redirectUri)}>
                        <X size="15" class="hover:text-red-500 cursor-pointer transition-all" />
                    </div>
                </Tooltip>
            </div>
        {/each}
    </div>
</div>