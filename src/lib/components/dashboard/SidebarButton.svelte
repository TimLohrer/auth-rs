<script lang="ts">
	import { ClipboardList, CodeXml, Crown, Laptop, Link, LogOut, ScrollText, Settings, Shield, TicketCheck, User, Users } from "lucide-svelte";

    export let tab: {
        name: string;
        icon: string;
    };
    export let active: boolean;
    export let selectTab: () => void;
    export let isLogout: boolean = false;
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div
    class="flex flex-row items-center justify-start gap-[15px] {isLogout ? 'w-full' : 'w-[275px]'} border-[2px] border-[#222] rounded-md cursor-pointer {isLogout ? 'hover:text-red-500' : 'hover:text-blue-500'} {isLogout ? 'hover:border-red-500' : 'hover:border-blue-500'} transition-all"
    class:active={active}
    style="padding: 10px 15px; margin-top: {isLogout ? '25' : '0'}px;"
    on:click={selectTab}
>
    {#if tab.icon == 'user'}
        <User height="30" width="30" />
    {:else if tab.icon == 'shield'}
        <Shield height="30" width="30" />
    {:else if tab.icon == 'laptop'}
        <Laptop height="30" width="30" />
    {:else if tab.icon == 'link'}
        <Link height="30" width="30" />
    {:else if tab.icon == 'code-xml'}
        <CodeXml height="30" width="30" />
    {:else if tab.icon == 'clipboard-list'}
        <ClipboardList height="30" width="30" />
    {:else if tab.icon == 'users'}
        <Users height="30" width="30" />
    {:else if tab.icon == 'crown'}
        <Crown height="30" width="30" />
    {:else if tab.icon == 'scroll-text'}
        <ScrollText height="30" width="30" />
    {:else if tab.icon == 'ticket-check'}
        <TicketCheck height="30" width="30" />
    {:else if tab.icon == 'settings'}
        <Settings height="30" width="30" />
    {:else if tab.icon == 'log-out'}
        <LogOut height="30" width="30" />
    {/if}
    <p>{tab.name}</p>
</div>

<style>
    .active {
        background-color: var(--color-blue-500);
        border-color: var(--color-blue-500);
    }

    .active:hover {
        color: white;
        cursor: default;
    }
</style>