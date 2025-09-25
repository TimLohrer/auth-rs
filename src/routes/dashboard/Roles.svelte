<script lang="ts">
	import Popup from '../../lib/components/global/Popup.svelte';
	import type AuthRsApi from "$lib/api";
	import { PackageOpen, Pen, Trash } from "lucide-svelte";
	import { onMount } from "svelte";
	import RoleUpdates from '$lib/models/RoleUpdates';
	import Role from '$lib/models/Role';
	import DateUtils from '$lib/dateUtils';
	import TextInput from '$lib/components/global/TextInput.svelte';
	import Tooltip from 'sv-tooltip';
	import { jsonAction } from '$lib/utils/jsonAttributes';

    export let api: AuthRsApi;
    export let roles: Role[];

    let showNewRolePopup: boolean = false;
    let newRole: Role | null = null;
    let newRoleName: string = '';

    let editRolePopup: boolean = false;
    let editRole: Role | null = null;
    let editRoleName: string = '';
    // let editRoleDescription: string = '';

    let deleteRolePopup: boolean = false;
    let deleteRole: Role | null = null;

    function openCreateRolePopup() {
        newRole = null;
        newRoleName = '';
        showNewRolePopup = true;
    }

    onMount(() => {
        api.getAllRoles()
            .then(allRoles => roles = allRoles)
            .catch(e => console.error(e));
    });
</script>

{#if showNewRolePopup}
    <Popup title="Create Role" onClose={() => showNewRolePopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px] max-w-[400px]">
            <TextInput label="Name" bind:value={newRoleName} autofocus />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {newRoleName.length > 3 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 25px; margin-bottom: 10px;"
                on:click={newRoleName.length > 3 ? () => {
                    showNewRolePopup = false;
                    api.createRole(newRoleName)
                        .then(createdRole => {
                            newRole = createdRole;
                            roles = [...roles, createdRole]
                        })
                        .catch(console.error);
                } : null}
            >Create</p>
        </div>
    </Popup>
{/if}

{#if editRolePopup}
    <Popup title="Edit Role" onClose={() => editRolePopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <TextInput label="Name" bind:value={editRoleName} autofocus />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editRoleName.length > 3 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 20px; margin-bottom: 10px;"
                on:click={editRoleName.length > 3 ? () => {
                    editRolePopup = false;
                    api.updateRole(editRole!, new RoleUpdates({ name: editRoleName }))
                        .then(newRole => {
                            roles[roles.map(app => app._id).indexOf(editRole!._id)] = newRole;
                        })
                        .catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if deleteRolePopup}
    <Popup title="Delete Role" onClose={() => deleteRolePopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to delete the role "{deleteRole?.name}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    deleteRolePopup = false;
                    api.deleteRole(deleteRole!)
                        .then(() => roles = roles.filter(app => app._id != deleteRole!._id))
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if roles.length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <PackageOpen size="75" class="opacity-40" />
        <p class="text-[20px] opacity-50">There are currently no roles set up.</p>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <p
                class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
                style="padding: 10px; margin-top: 25px;"
                on:click={openCreateRolePopup}
            >Create Role</p>
    </div>
{:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <p
            class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
            style="padding: 10px;"
            on:click={openCreateRolePopup}
        >Create Role</p>
    </div>
    <div class="flex flex-wrap overflow-y-scroll overflow-x-hidden gap-[25px]">
        {#each roles as role}
            <div
                class="flex flex-col items-start justify-start gap-[10px] min-w-[250px] max-w-[400px] min-h-[135px] border-[2px] border-[#333] rounded-md"
                style="padding: 15px;"
                use:jsonAction={{ data: role, title: "Role Data" }}
            >
                <div class="flex flex-row justify-between gap-[20px] w-full">
                    <p class="text-[20px] font-bold h-[20px]">{role.name.length > 20 ? role.name.substring(0, 19) + '...' : role.name}</p>
                    {#if !role.system}
                        <div class="flex flex-row">
                            <Tooltip tip="Edit Role" bottom>
                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                <div class="flex self-end" style="margin-right: 12.5px;" on:click={() => {
                                    editRole = role;
                                    editRoleName = role.name;
                                    editRolePopup = true;
                                }}>
                                    <Pen
                                        class="cursor-pointer hover:text-blue-500 transition-all"
                                        size=20
                                    />
                                </div>
                            </Tooltip>
                            <Tooltip tip="Delete Role" bottom color="var(--color-red-600)">
                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                <div class="flex self-end" on:click={() => {
                                    deleteRole = role;
                                    deleteRolePopup = true;
                                }}>
                                    <Trash
                                        class="cursor-pointer hover:text-red-600 transition-all"
                                        size=20
                                    />
                                </div>
                            </Tooltip>
                        </div>
                    {/if}
                </div>
                <p class="text-[12px] opacity-35 h-[20px]">Created at {DateUtils.getDateString(Role.getCreatedAt(role))}</p>
                {#if role.system}
                    <p class="text-[12px] opacity-35 h-[20px] max-w-[250px]">This is a system role wich cannot be edited or deleted.</p>
                {/if}
            </div>
        {/each}
    </div>
{/if}