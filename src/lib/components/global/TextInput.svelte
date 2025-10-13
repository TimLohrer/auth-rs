<script lang="ts">
	import { Eye, EyeOff } from "lucide-svelte";
	import type { FullAutoFill } from "svelte/elements";

    export let label: string;
    export let value: any;
    export let type: "text" | "password" | "email" | "number" = "text";
    export let placeholder: string | null = null;
    export let autofocus: boolean | null = false;
    export let autocomplete: FullAutoFill | null = null;
    export let disabled: boolean | null = false;

    let hidePassword = true;
</script>

<div class="flex flex-col w-[100%] items-center justify-center" class:opacity-50={disabled}>
    {#if label.length > 0}
        <p class="text-[14px] self-start h-[17.5px] opacity-50">{label}</p>
    {/if}
    <!-- svelte-ignore a11y_autofocus -->
    <input
        type={type == 'password' && !hidePassword ? 'text' : type}
        placeholder={placeholder ?? label ?? ''}
        bind:value
        autocomplete={autocomplete}
        disabled={disabled}
        class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
        style="padding: 5px 10px; margin-top: 5px; margin-bottom: 10px;"
        on:input={type != 'number' ? null : (e) => (e.target as HTMLInputElement).value = Math.floor(Number((e.target as HTMLInputElement).value)).toString()}
        autofocus={autofocus}
    >   
    {#if type == 'password'}
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <span
            
            class="absolute cursor-pointer self-end"
            style="margin-right: 10px; {label.length > 0 ? 'margin-bottom: -12.5px;' : 'margin-bottom: 5px;'}"
            on:click={() => hidePassword = !hidePassword}
        >
            {#if hidePassword}
                <EyeOff class="size-[18px]" />
            {:else}
                <Eye class="size-[18px]" />
            {/if}
        </span>
    {/if}
</div>

<style>
    input:focus {
        outline: none;
        border: solid 1.5px var(--color-blue-500);
    }
</style>