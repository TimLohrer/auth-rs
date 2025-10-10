<script lang="ts">
	import { X } from "lucide-svelte";
	import { onMount } from "svelte";

    export let title: string;
    export let onClose: () => void;

    function close() {
        document.getElementById('background')?.animate([
            { opacity: 0.85 },
            { opacity: 0 }
        ], {
            duration: 300,
            easing: 'ease-in-out',
            fill: 'forwards'
        });
        document.getElementById('popup')?.animate([
            { opacity: 1, transform: 'translateY(0)' },
            { opacity: 0, transform: 'translateY(10%)' }
        ], {
            duration: 200,
            easing: 'ease-in-out',
            fill: 'forwards'
        });

        setTimeout(() => {
            onClose();
        }, 200);
    }

    onMount(() => {
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                onClose();
            }
        });

        document.getElementById('background')?.animate([
            { opacity: 1 },
            { opacity: 0.85 }
        ], {
            duration: 300,
            easing: 'ease-in-out',
            fill: 'forwards'
        });
        document.getElementById('popup')?.animate([
            { opacity: 0, transform: 'translateY(10%)' },
            { opacity: 1, transform: 'translateY(0)' }
        ], {
            duration: 200,
            easing: 'ease-in-out',
            fill: 'forwards'
        });
    });
</script>

<!-- svelte-ignore element_invalid_self_closing_tag -->
<div id="background" class="absolute flex items-center justify-center top-0 left-0 w-full h-full opacity-85 bg-black z-[999]" />
<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div class="absolute flex items-center justify-center top-0 left-0 w-full h-full z-[1000] overflow-hidden" on:mousedown={close}>
    <div id="popup" class="flex flex-col gap-[7.5px] bg-black border-[2px] border-[#222] max-h-[80%] max-w-[80%] rounded-md" style="padding: 10px;" on:mousedown={e => e.stopPropagation()}>
        <div class="flex flex-row min-w-[300px] items-center justify-between">
            <p>{title}</p>
            <!-- svelte-ignore a11y_no_static_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <div class="flex items-center justify-center" on:click={close}>
                <X size="24" class="cursor-pointer hover:text-red-600 transition-all" />
            </div>
        </div>
        <!-- svelte-ignore element_invalid_self_closing_tag -->
        <div class="w-full h-[2px] rounded-md bg-[#111]" />
        <slot />
    </div>
</div>