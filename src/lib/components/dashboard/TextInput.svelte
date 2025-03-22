<script lang="ts">
    export let label: string;
    export let value: any;
    export let type: "text" | "password" | "email" = "text";
    export let placeholder: string | null = null;
</script>

<p class="text-[14px] self-start h-[17.5px] opacity-50">{label}</p>
<!-- svelte-ignore a11y_autofocus -->
<input
    type={type}
    placeholder={placeholder ?? label ?? ''}
    bind:value
    class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
    style="padding: 5px 10px; margin-top: 5px; margin-bottom: 10px;"
>

<style>
    input:focus {
        outline: none;
        border: solid 1.5px var(--color-blue-500);
    }
</style>