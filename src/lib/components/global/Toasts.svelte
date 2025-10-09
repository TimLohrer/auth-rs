<script lang="ts">
    import { activeToasts } from '$lib/store/toastStore';
</script>

<div class="absolute w-screen h-screen top-0 left-0 z-50" style="pointer-events: none;">
    {#each $activeToasts.toReversed() as toast, index}
        <div
            class="flex w-fit min-w-[250px] min-h-[50px] h-[50px] bg-black border-[2.5px] absolute right-5 bottom-5 {toast.type == 'error' ? 'border-red-500' : toast.type == 'success' ? 'border-green-500' : 'border-blue-500'} rounded-md items-center"
            style="margin-bottom: {index * 60}px;"
        >
            {#if toast.type === 'success'}
                <div class="bg-green-500 w-[5px] h-full"></div>
            {:else if toast.type === 'error'}
                <div class="bg-red-500 w-[5px] h-full"></div>
            {:else if toast.type === 'info'}
                <div class="bg-blue-500 w-[5px] h-full"></div>
            {/if}
            <p class="text-[14px]" style="margin: 10px;">{toast.message}</p>
        </div>
    {/each}
</div>