<script lang="ts">
	import type Role from "$lib/models/Role";
	import User from "$lib/models/User";
	import { jsonAction, jsonAttributes } from "$lib/utils/jsonAttributes";
	import { PlusCircle, X } from "lucide-svelte";
	import Tooltip from "sv-tooltip";

    export let label: string;
    export let roles: Role[];
    export let readOnly: boolean = true;
    export let disableOutline: boolean = false;
    export let isSystemAdmin: boolean = false;
    export let emptyText: string = "No roles assigned.";
    export let onAdd: () => void;
    export let onRemove: (role: Role) => void;
</script>

<div class="flex flex-col">
    <div class="flex flex-row items-center">
        <p class="text-[14px]" style="padding: 2px 6px;">{label}</p>
        {#if !readOnly}
            <Tooltip tip="Add Role" right>
                <!-- svelte-ignore a11y_no_static_element_interactions -->
                <!-- svelte-ignore a11y_click_events_have_key_events -->
                <div on:click={onAdd}>
                    <PlusCircle size="15" class="hover:text-green-500 cursor-pointer transition-all" />
                </div>
            </Tooltip>
        {/if}
    </div>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="name-input flex items-center flex-wrap outline-none gap-[10px] rounded-md w-[275px] {disableOutline ? '' : 'border-[2px] border-[#333]'}" style={disableOutline ? "" : "padding: 10px;"}>
        {#each roles as role}
            <div
                class="flex flex-row items-center justify-between gap-[10px] text-[13px] h-[40px] bg-[#111] rounded-md"
                style="padding: 10px; {disableOutline ? 'margin: 0 2.5px;' : ''}"
                use:jsonAction={{ data: role, title: "Role Data" }}
            >
                <p style="color: white !important;">{role.name}</p>
                {#if role.id != User.DEFAULT_ROLEid && !(role.id == User.ADMIN_ROLEid && !isSystemAdmin) && !readOnly}
                    <Tooltip tip="Remove Role" right color="var(--color-red-600)">
                        <div on:click={() => onRemove(role)}>
                            <X size="15" class="hover:text-red-500 cursor-pointer transition-all" />
                        </div>
                    </Tooltip>
                {/if}
            </div>
        {/each}
        {#if roles.length == 0}
            <i class="text-[13px] text-[#777]" style="margin-left: 7.5px; margin-top: 5px">{emptyText}</i>
        {/if}
    </div>
</div>