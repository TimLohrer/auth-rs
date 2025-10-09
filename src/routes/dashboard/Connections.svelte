<script lang="ts">
	import ScopeList from '../../lib/components/global/ScopeList.svelte';
	import type AuthRsApi from "$lib/api";
	import OAuthConnection from "$lib/models/OAuthConnection";
	import type User from "$lib/models/User";
	import { Trash, Unlink } from "lucide-svelte";
	import { onMount } from "svelte";
	import Popup from '$lib/components/global/Popup.svelte';
	import DateUtils from '$lib/utils/dateUtils';
	import Tooltip from 'sv-tooltip';
	import { jsonAction } from '$lib/utils/jsonAttributes';

    export let api: AuthRsApi;
    export let user: User;
    export let connections: OAuthConnection[];

    let unlinkConnectionPopup: boolean = false;
    let unlinkConnection: OAuthConnection | null = null;

    onMount(() => {
        api.getConnections(user)
            .then(apps => connections = apps)
            .catch(e => console.error(e));
    });
</script>

{#if unlinkConnectionPopup}
    <Popup title="Unlink Connection" onClose={() => {unlinkConnectionPopup = false; unlinkConnection = null;}}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to unlink the application "{unlinkConnection!.application.name}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    unlinkConnectionPopup = false;
                    api.disconnectConnection(unlinkConnection!)
                        .then(() => connections = connections.filter(c => c._id != unlinkConnection!._id))
                        .catch(e => console.error(e));
                }}
            >Unlink</p>
        </div>
    </Popup>
{/if}

{#if connections.length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <Unlink size="75" class="opacity-40" />
        <p class="text-[20px] opacity-50">You don't have any connected Apps.</p>
    </div>
{:else}
    <div class="flex flex-wrap w-full overflow-y-scroll overflow-x-hidden gap-[25px]">
        {#each connections as connection}
            <div
                class="flex flex-col items-start justify start gap-[10px] w-[350px] min-h-[200px] border-[2px] border-[#333] rounded-md"
                style="padding: 15px;"
                use:jsonAction={{ data: connection, title: "Connection Data" }}
            >
                <div class="flex flex-row justify-between w-full">
                    <p class="text-[20px] font-bold h-[20px]">{connection.application.name}</p>
                    <div class="flex flex-row">
                        <Tooltip tip={OAuthConnection.getExpiresAt(connection).getTime() >= 0 ? "Unlink Connection" : "Delete Connection"} bottom color="var(--color-red-600)">
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <div class="flex self-end" on:click={() => {
                                unlinkConnection = connection;
                                unlinkConnectionPopup = true;
                            }}>
                                {#if OAuthConnection.getExpiresAt(connection).getTime() >= 0}
                                    <Unlink
                                        class="cursor-pointer hover:text-red-600 transition-all"
                                        size=20
                                    />
                                {:else}
                                    <Trash
                                        class="cursor-pointer hover:text-red-600 transition-all"
                                        size=20
                                    />
                                {/if}
                            </div>
                        </Tooltip>
                    </div>
                </div>
                <p class="text-[12px] opacity-35 h-[10px]">Authorized at {DateUtils.getFullDateString(OAuthConnection.getCreatedAt(connection))}</p>
                {#if OAuthConnection.getExpiresAt(connection).getTime() >= 0}
                    <p class="text-[12px] opacity-75 h-[20px] text-green-600">Expires in {DateUtils.getDurationString(OAuthConnection.getExpiresAt(connection).getTime())}</p>
                {:else}
                    <p class="text-[12px] opacity-75 h-[20px] text-red-600">Expired!</p>
                {/if}
                <p class="text-[12px] opacity-50">{@html (connection.application.description?.length ?? 0) > 1 ? connection.application.description?.substring(0, 200) + ((connection.application.description?.length ?? 0) > 200 ? '...' : '') : '<i>This app does not have a description.</i>'}</p>
                <p class="text-[12px] h-[10px]">Permissions:</p>
                <div class="flex flex-col w-full">
                    <ScopeList scopes={connection.scope} iconSize={17.5} textSize="14px" gap="10px" />
                </div> 
            </div>
        {/each}
    </div>
{/if}