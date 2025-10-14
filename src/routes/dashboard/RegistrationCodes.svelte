<script lang="ts">
	import TextInput from '../../lib/components/global/TextInput.svelte';
	import Popup from '../../lib/components/global/Popup.svelte';
	import type AuthRsApi from "$lib/api";
	import { Pen, Share, TicketX, Trash } from "lucide-svelte";
	import { onMount } from "svelte";
	import RegistrationTokenUpdates from '$lib/models/RegistrationTokenUpdates';
	import RegistrationToken from '$lib/models/RegistrationToken';
	import TextField from '$lib/components/global/TextField.svelte';
	import RoleList from '$lib/components/dashboard/RoleList.svelte';
	import Role from '$lib/models/Role';
	import DateUtils from '$lib/utils/dateUtils';
	import User from '$lib/models/User';
	import Tooltip from 'sv-tooltip';
	import { jsonAction } from '$lib/utils/jsonAttributes';

    export let api: AuthRsApi;
    export let currentUser: User;
    export let users: User[];
    export let roles: Role[];
    export let registrationTokens: RegistrationToken[];

    let showNewRegistrationTokenPopup: boolean = false;
    let newRegistrationTokenMaxUses: number = 1;
    let newRegistrationTokenExpiresIn: number = 0;
    let newRegistrationTokenExpiresInInput: number = 1;
    let newRegistrationTokeneEpiresInIndex: number = 0;

    let editRegistrationTokenPopup: boolean = false;
    let editRegistrationToken: RegistrationToken | null = null;
    let editRegistrationTokenMaxUses: number = 1;
    let editRegistrationTokenExpiresIn: number = 0;
    let editRegistrationTokenExpiresInInput: number = 1;
    let editRegistrationTokenExpiresInIndex: number = 0;

    let showAddRegistrationTokenAutoRolesPopup: RegistrationToken | null = null;
    let addRegistrationTokenAutoRoles: Role[] = [];

    let deleteRegistrationTokenPopup: boolean = false;
    let deleteRegistrationToken: RegistrationToken | null = null;

    function openCreateRegistrationTokenPopup() {
        newRegistrationTokenMaxUses = 1;
        newRegistrationTokenExpiresIn = 0;
        newRegistrationTokeneEpiresInIndex = 0;
        showNewRegistrationTokenPopup = true;
    }

    function removeRole(role: Role, token: RegistrationToken) {
        const updates = new RegistrationTokenUpdates({ 
            maxUses: null,
            expiresIn: null,
            autoRoles: token.autoRoles.filter(roldId => roldId != role.id),
        });
        api.updateRegistrationToken(token, updates)
            .then(token => registrationTokens[registrationTokens.map(t => t.id).indexOf(token.id)] = token)
            .catch(e => console.error(e));
    }

    function getExpiresIn(index: number, input: number): number {
        switch (index) {
            case 0:
                return input * 60 * 60 * 1000;
            case 1:
                return input * 60 * 60 * 24 * 1000;
            case 2:
                return input * 60 * 60 * 24 * 7 * 1000;
            case 3:
                return input * 60 * 60 * 24 * 30 * 1000;
            default:
                return 0;
        }
    }

    function getInputAndIndexFromExpiresIn(expiresIn: number | null) {
        if (expiresIn == null || expiresIn == 0) {
            return [0, 4];
        } else if (expiresIn % (60 * 60 * 24 * 30 * 1000) == 0) {
            return [expiresIn / (60 * 60 * 24 * 30 * 1000), 3];
        } else if (expiresIn % (60 * 60 * 24 * 7 * 1000) == 0) {
            return [expiresIn / (60 * 60 * 24 * 7 * 1000), 2];
        } else if (expiresIn % (60 * 60 * 24 * 1000) == 0) {
            return [expiresIn / (60 * 60 * 24 * 1000), 1];
        } else if (expiresIn % (60 * 60 * 1000) == 0) {
            return [expiresIn / (60 * 60 * 1000), 0];
        }

        return [0, 4];
    }

    onMount(() => {
        api.getAllRegistrationTokens()
            .then(allRegistrationTokens => registrationTokens = allRegistrationTokens)
            .catch(e => console.error(e));

        if (roles.length < 1) {
            api.getAllRoles()
                .then(allRoles => roles = allRoles)
                .catch(e => console.error(e));
        }
        
        if (users.length < 1) {
            api.getAllUsers()
                .then(allUsers => users = allUsers)
                .catch(e => console.error(e));
        }
    });
</script>

{#if showNewRegistrationTokenPopup}
    <Popup title="Create Registration Code" onClose={() => showNewRegistrationTokenPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px] max-w-[500px]">
            <TextInput type="number" label="Maximum Uses" bind:value={newRegistrationTokenMaxUses} autofocus />
            <p class="text-[14px] self-start h-[17.5px] opacity-50">Expires In</p>
            <div class="flex flex-row gap-[10px] h-[50px] w-full items-center justify-between cursor-pointer" style="margin: 0 10px;">
                {#each ['Hour(s)', 'Day(s)', 'Week(s)', 'Month(s)', 'Never'] as item, index}
                    <!-- svelte-ignore a11y_click_events_have_key_events -->
                    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
                    <p class="bg-[#222] {newRegistrationTokeneEpiresInIndex == index ? 'text-blue-600' : ''} h-min rounded-md" style="padding: 5px 10px;" on:click={() => newRegistrationTokeneEpiresInIndex = index}>{item}</p>
                {/each}
            </div>
            {#if newRegistrationTokeneEpiresInIndex != 4}
                <TextInput type="number" label="" bind:value={newRegistrationTokenExpiresInInput} />
            {/if}
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {newRegistrationTokenMaxUses > 0 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 25px; margin-bottom: 10px;"
                on:click={newRegistrationTokenMaxUses > 0 ? () => {
                    showNewRegistrationTokenPopup = false;
                    newRegistrationTokenExpiresInInput = getExpiresIn(newRegistrationTokeneEpiresInIndex, newRegistrationTokenExpiresInInput);

                    api.createRegistrationToken(newRegistrationTokenMaxUses, newRegistrationTokenExpiresInInput > 0 ? newRegistrationTokenExpiresInInput : null)
                        .then(createdRegistrationToken => {
                            registrationTokens = [...registrationTokens, createdRegistrationToken]
                        })
                        .catch(console.error);
                } : null}
            >Create</p>
        </div>
    </Popup>
{/if}

{#if editRegistrationTokenPopup}
    <Popup title="Edit Registration Code" onClose={() => editRegistrationTokenPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <TextInput type="number" label="Maximum Uses" bind:value={editRegistrationTokenMaxUses} autofocus />
            <p class="text-[14px] self-start h-[17.5px] opacity-50" style="margin-top: 5px;">Expires In</p>
            <div class="flex flex-row gap-[10px] h-[50px] w-full items-center justify-between cursor-pointer" style="margin: 0 10px;">
                {#each ['Hour(s)', 'Day(s)', 'Week(s)', 'Month(s)', 'Never'] as item, index}
                    <!-- svelte-ignore a11y_click_events_have_key_events -->
                    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
                    <p class="bg-[#222] {editRegistrationTokenExpiresInIndex == index ? 'text-blue-600' : ''} h-min rounded-md" style="padding: 5px 10px;" on:click={() => editRegistrationTokenExpiresInIndex = index}>{item}</p>
                {/each}
            </div>
            {#if editRegistrationTokenExpiresInIndex != 4}
                <TextInput type="number" label="" bind:value={editRegistrationTokenExpiresInInput} />
            {/if}
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editRegistrationTokenMaxUses > 0 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 20px; margin-bottom: 10px;"
                on:click={editRegistrationTokenMaxUses > 0 ? () => {
                    editRegistrationTokenPopup = false;
                    editRegistrationTokenExpiresIn = getExpiresIn(editRegistrationTokenExpiresInIndex, editRegistrationTokenExpiresInInput);

                    api.updateRegistrationToken(editRegistrationToken!, new RegistrationTokenUpdates({ maxUses: editRegistrationTokenMaxUses, expiresIn: editRegistrationTokenExpiresIn < 1 ? null : editRegistrationTokenExpiresIn, autoRoles: null }))
                        .then(editedRegistrationToken => {
                            registrationTokens[registrationTokens.map(t => t.id).indexOf(editRegistrationToken!.id)] = editedRegistrationToken;
                        })
                        .catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if showAddRegistrationTokenAutoRolesPopup}
    <Popup title="Add Auto Roles" onClose={() => {showAddRegistrationTokenAutoRolesPopup = null; addRegistrationTokenAutoRoles = [];}}>
        <div class="flex flex-col items-center justify-center">
            {#if roles.filter(r => {
                let token: RegistrationToken = registrationTokens.find(token => token.id == showAddRegistrationTokenAutoRolesPopup?.id)!;
                return !token.autoRoles.includes(r.id) && r.id != User.DEFAULT_ROLEid;
            }).length < 1}
                <i>Registration Code already has every auto role.</i>
                <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
                <!-- svelte-ignore a11y_click_events_have_key_events -->
                <p
                    class="text-red-600 rounded-md cursor-pointer text-[18px]"
                    style="margin-top: 20px; margin-bottom: 10px;"
                    on:click={() => showAddRegistrationTokenAutoRolesPopup = null}
                >Close</p>
            {:else} 
                <div class="flex flex-col items-center justify-center max-w-[600px] max-h-[300px] gap-[25px]">
                    <i class="text-[14px] text-[#777] w-[400px] text-center">Selected auto roles will automatically be added to users that register their account using this code.</i>
                    <div class="flex flex-wrap items-center justify-center overflow-y-scroll gap-[25px]">
                        {#each roles.filter(r => {
                            let token: RegistrationToken = registrationTokens.find(token => token.id == showAddRegistrationTokenAutoRolesPopup?.id)!;
                            return !token.autoRoles.includes(r.id) && r.id != User.DEFAULT_ROLEid;
                        }) as role}
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <div
                                class="cursor-pointer {addRegistrationTokenAutoRoles.map(r => r.id).includes(role.id) ? 'border-green-600' : 'border-[#333]'} border-[1px] rounded-md"
                                on:click={() => {
                                    const roleIds = addRegistrationTokenAutoRoles.map(r => r.id);
                                    
                                    if (roleIds.includes(role.id)) {
                                        addRegistrationTokenAutoRoles = addRegistrationTokenAutoRoles.filter(r => r.id != role.id);
                                    } else {
                                        addRegistrationTokenAutoRoles = [...addRegistrationTokenAutoRoles, role];
                                    }
                                }}
                                style="padding: 10px;"
                            >
                                <p>{role.name}</p>
                            </div>
                        {/each}
                    </div>
                </div>
                <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
                <!-- svelte-ignore a11y_click_events_have_key_events -->
                <p
                    class="text-green-600 rounded-md {addRegistrationTokenAutoRoles.length > 0 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                    style="margin-top: 20px; margin-bottom: 10px;"
                    on:click={addRegistrationTokenAutoRoles.length > 0 ? () => {
                        api.updateRegistrationToken(showAddRegistrationTokenAutoRolesPopup!, new RegistrationTokenUpdates({
                            maxUses: null,
                            expiresIn: null,
                            autoRoles: registrationTokens.find(t => t.id == showAddRegistrationTokenAutoRolesPopup?.id)?.autoRoles.concat(addRegistrationTokenAutoRoles.map(r => r.id)) ?? null,
                        })).then(editedRegistrationToken => {
                            registrationTokens[registrationTokens.map(t => t.id).indexOf(showAddRegistrationTokenAutoRolesPopup!.id)] = editedRegistrationToken;
                            showAddRegistrationTokenAutoRolesPopup = null;
                            addRegistrationTokenAutoRoles = [];
                        }).catch(e => {
                            console.error(e);
                            showAddRegistrationTokenAutoRolesPopup = null;
                            addRegistrationTokenAutoRoles = [];
                        });
                    } : null}
                >Add</p>
            {/if}
        </div>
    </Popup>
{/if}

{#if deleteRegistrationTokenPopup}
    <Popup title="Delete Registration Code" onClose={() => deleteRegistrationTokenPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to delete the user "{deleteRegistrationToken?.code}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    deleteRegistrationTokenPopup = false;
                    api.deleteRegistrationToken(deleteRegistrationToken!)
                        .then(() => registrationTokens = registrationTokens.filter(token => token.id != deleteRegistrationToken!.id))
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if registrationTokens.length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <TicketX size="75" class="opacity-40" />
            <p class="text-[20px] opacity-50">There are currently no registration tokens set up.</p>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <p
                class="border-blue-500 text-blue-500 bg-black hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
                style="padding: 10px; margin-top: 25px;"
                on:click={openCreateRegistrationTokenPopup}
            >Create Registration Code</p>
    </div>
{:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <p
            class="border-blue-500 text-blue-500 bg-black hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
            style="padding: 10px;"
            on:click={openCreateRegistrationTokenPopup}
        >Create Registration Code</p>
    </div>
    <div class="flex flex-wrap overflow-y-scroll overflow-x-hidden gap-[25px]">
        {#each registrationTokens as token}
            <div
                class="flex flex-col items-start justify start gap-[10px] min-w-[300px] border-[2px] border-[#333] rounded-md"
                style="padding: 15px;"
                use:jsonAction={{ data: token, title: "Registration Token Data" }}
            >
                <div class="flex flex-row justify-between w-full gap-[20px]">
                    <p class="text-[20px] font-bold h-[20px]">{token.code}</p>
                    <div class="flex flex-row">
                        <Tooltip tip="Copy Link" bottom color="var(--color-green-600)">
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <div class="flex self-end" style="margin-right: 15px;" on:click={() => {
                                (document.getElementById(`copy-url-${token.id}`) as HTMLInputElement)!.focus();
                                (document.getElementById(`copy-url-${token.id}`) as HTMLInputElement)!.select();
                                document.execCommand('copy');
                            }}>
                                <Share
                                    class="cursor-pointer hover:text-green-600 transition-all"
                                    size=20
                                />
                            </div>
                            <input type="text" id={`copy-url-${token.id}`} value={RegistrationToken.getUrl(token)} class="w-[1px] h-[1px] absolute opacity-0" />
                        </Tooltip>
                        <Tooltip tip="Edit Registartion Code" bottom>
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <div class="flex self-end" style="margin-right: 15px;" on:click={() => {
                                const [input, index] = getInputAndIndexFromExpiresIn(token.expiresIn);
                                editRegistrationToken = token;
                                editRegistrationTokenMaxUses = token.maxUses;
                                editRegistrationTokenExpiresInInput = input;
                                editRegistrationTokenExpiresInIndex = index;
                                editRegistrationTokenExpiresIn = token.expiresIn ?? 0;
                                editRegistrationTokenPopup = true;
                            }}>
                                <Pen
                                    class="cursor-pointer hover:text-blue-500 transition-all"
                                    size=20
                                />
                            </div>
                        </Tooltip>
                        <Tooltip tip="Delete Registration Code" bottom color="var(--color-red-600)">
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <div class="flex self-end" on:click={() => {
                                deleteRegistrationToken = token;
                                deleteRegistrationTokenPopup = true;
                            }}>
                                <Trash
                                    class="cursor-pointer hover:text-red-600 transition-all"
                                    size=20
                                />
                            </div>
                        </Tooltip>
                    </div>
                </div>
                <p class="text-[12px] opacity-35 h-[10px]">Created at {DateUtils.getFullDateString(RegistrationToken.getCreatedAt(token))}</p>
                {#if token.expiresIn == null || token.expiresIn == 0}
                    <p class="text-[12px] opacity-75 {token.uses.length >= token.maxUses ? 'h-[10px]' : 'h-[20px]'} text-green-600">Never expires!</p>
                {:else if (RegistrationToken.getCreatedAt(token).getTime() + (RegistrationToken.getExpiresAt(token)?.getTime() ?? 0)) - Date.now() >= 0}
                    <p class="text-[12px] opacity-75 {token.uses.length >= token.maxUses ? 'h-[10px]' : 'h-[20px]'} text-green-600">Expires in {DateUtils.getDurationString(RegistrationToken.getExpiresAt(token)!.getTime())}</p>
                {:else}
                    <p class="text-[12px] opacity-75 {token.uses.length >= token.maxUses ? 'h-[10px]' : 'h-[20px]'} text-red-600">Expired!</p>
                {/if}
                {#if token.uses.length >= token.maxUses}
                    <p class="text-[12px] opacity-75 h-[20px] text-red-600">Max uses reached!</p>
                {/if}
                <TextField
                    label="Maximum Uses"
                    value={token.maxUses > 0 ? token.maxUses.toString() : 'Unlimited'}
                    readonly
                />
                <TextField
                    label="Uses"
                    value={token.uses.length.toString()}
                    readonly
                />
                <RoleList
                    label="Auto Roles"
                    roles={roles.filter(r => token.autoRoles.includes(r.id))}
                    onAdd={() => showAddRegistrationTokenAutoRolesPopup = token}
                    onRemove={(role: Role) => removeRole(role, token)}
                    readOnly={false}
                    isSystemAdmin={User.isSystemAdmin(currentUser)}
                    emptyText="No auto roles assigned."
                    disableOutline
                />
            </div>
        {/each}
    </div>
{/if}