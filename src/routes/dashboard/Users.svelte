<script lang="ts">
	import TextInput from './../../lib/components/dashboard/TextInput.svelte';
	import Popup from '../../lib/components/global/Popup.svelte';
	import type AuthRsApi from "$lib/api";
	import { PackageOpen, Pen, Trash, UserCheck, UserX } from "lucide-svelte";
	import { onMount } from "svelte";
	import UserMinimalUpdates from '$lib/models/UserUpdates';
	import UserMinimal from '$lib/models/User';
	import TextField from '$lib/components/dashboard/TextField.svelte';
	import RoleList from '$lib/components/dashboard/RoleList.svelte';
	import type Role from '$lib/models/Role';

    export let api: AuthRsApi;
    export let currentUser: UserMinimal;
    export let users: UserMinimal[];
    export let roles: Role[];

    let showNewUserPopup: boolean = false;
    let newUser: UserMinimal | null = null;
    let newUserEmail: string = '';
    let newUserFirstName: string = '';
    let newUserLastName: string = '';
    let newUserPassword: string = '';
    let newUserPasswordConfirm: string = '';

    let editUserPopup: boolean = false;
    let editUser: UserMinimal | null = null;
    let editUserEmail: string = '';
    let editUserFirstName: string = '';
    let editUserLastName: string = '';
    let editUserPassword: string = '';
    let editUserPasswordConfirm: string = '';

    let disableUserPopup: boolean = false;
    let disableUser: UserMinimal | null = null;

    let enableUserPopup: boolean = false;
    let enableUser: UserMinimal | null = null;

    let deleteUserPopup: boolean = false;
    let deleteUser: UserMinimal | null = null;

    function openCreateUserPopup() {
        newUser = null;
        newUserEmail = '';
        newUserFirstName = '';
        newUserLastName = '';
        newUserPassword = '';
        newUserPasswordConfirm = '';
        showNewUserPopup = true;
    }

    $: newUserDataIsValid = () => {
        const emailValid = newUserEmail.length > 3 && newUserEmail.includes('@') && newUserEmail.includes('.');
        const nameValid = newUserFirstName.length > 1;
        const passwordValid = newUserPassword.length > 7 && newUserPassword === newUserPasswordConfirm;

        return emailValid && nameValid && passwordValid;
    }

    $: editUserDataIsValid = () => {
        const emailValid = editUserEmail.length >= 5 && editUserEmail.includes('@') && editUserEmail.includes('.');
        const nameValid = editUserFirstName.length > 0;
        const passwordValid = (editUserPassword.length < 1 && editUserPasswordConfirm.length < 1) || (editUserPassword.length > 7 && editUserPassword === editUserPasswordConfirm);

        return emailValid && nameValid && passwordValid;
    }

    onMount(() => {
        api.getAllUsers()
            .then(allUsers => users = allUsers)
            .catch(e => console.error(e));
    });
</script>

{#if showNewUserPopup}
    <Popup title="Create User" onClose={() => showNewUserPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px] max-w-[400px]">
            <TextInput label="Email" bind:value={newUserEmail} />
            <TextInput label="First Name" bind:value={newUserFirstName} />
            <TextInput label="Last Name" bind:value={newUserLastName} />
            <TextInput label="Password" bind:value={newUserPassword} type="password" />
            <TextInput label="Confirm Password" bind:value={newUserPasswordConfirm} type="password" />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {newUserDataIsValid() ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px] button green-button"
                style="margin-top: 25px; margin-bottom: 10px;"
                on:click={newUserDataIsValid() ? () => {
                    showNewUserPopup = false;
                    api.createUser(newUserEmail, newUserPassword, newUserFirstName, newUserLastName)
                        .then(createdUser => {
                            newUser = createdUser;
                            users = [...users, createdUser]
                        })
                        .catch(console.error);
                } : null}
            >Create</p>
        </div>
    </Popup>
{/if}

{#if editUserPopup}
    <Popup title="Edit User" onClose={() => editUserPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <TextInput label="Email" bind:value={editUserEmail}  />
            <TextInput label="First Name" bind:value={editUserFirstName}  />
            <TextInput label="Last Name" bind:value={editUserLastName}  />
            <TextInput label="Password" bind:value={editUserPassword}  />
            <TextInput label="Confirm Password" bind:value={editUserPasswordConfirm}  />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editUserDataIsValid() ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px] button green-button"
                style="margin-top: 20px; margin-bottom: 10px;"
                on:click={editUserDataIsValid() ? () => {
                    editUserPopup = false;
                    api.updateUser(editUser!, new UserMinimalUpdates({ email: editUserEmail, password: editUserPassword.length < 1 ? null : editUserPassword, firstName: editUserFirstName, lastName: editUserLastName, roles: null, disabled: null }))
                        .then(editedUser => {
                            users[users.map(user => user._id).indexOf(editUser!._id)] = editedUser;
                        })
                        .catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if disableUserPopup}
    <Popup title="Disable User" onClose={() => disableUserPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to disable the user "{disableUser?.firstName} {disableUser?.lastName}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px] button red-button"
                style="margin-top: 25px;"
                on:click={() => {
                    deleteUserPopup = false;
                    api.updateUser(disableUser!, new UserMinimalUpdates({ email: null, password: null, firstName: null, lastName: null, roles: null, disabled: true }))
                        .then(disabledUser => {
                            users[users.map(user => user._id).indexOf(disableUser!._id)] = disabledUser;
                        })
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if enableUserPopup}
    <Popup title="Enable User" onClose={() => enableUserPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to enable the user "{enableUser?.firstName} {enableUser?.lastName}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 cursor-pointer rounded-md text-[18px] button red-button"
                style="margin-top: 25px;"
                on:click={() => {
                    enableUserPopup = false;
                    api.updateUser(enableUser!, new UserMinimalUpdates({ email: null, password: null, firstName: null, lastName: null, roles: null, disabled: false }))
                        .then(enabledUser => {
                            users[users.map(user => user._id).indexOf(enableUser!._id)] = enabledUser;
                        })
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if deleteUserPopup}
    <Popup title="Delete User" onClose={() => deleteUserPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to delete the user "{deleteUser?.firstName} {deleteUser?.lastName}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px] button red-button"
                style="margin-top: 25px;"
                on:click={() => {
                    deleteUserPopup = false;
                    api.deleteUser(deleteUser!)
                        .then(() => users = users.filter(user => user._id != deleteUser!._id))
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if users.filter(u => u._id != UserMinimal.DEFAULT_USER_ID).length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <PackageOpen size="75" class="opacity-40" />
            <p class="text-[20px] opacity-50">There are currently no users set up.</p>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <p
                class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md button"
                style="padding: 10px; margin-top: 25px;"
                on:click={openCreateUserPopup}
            >Create User</p>
    </div>
{:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <p
            class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md button"
            style="padding: 10px;"
            on:click={openCreateUserPopup}
        >Create User</p>
    </div>
    <div class="flex flex-wrap overflow-y-scroll gap-[25px]">
        {#each users.filter(u => u._id != UserMinimal.DEFAULT_USER_ID) as user}
            <div class="flex flex-col items-start justify start gap-[10px] min-w-[300px] border-[2px] border-[#333] rounded-md" style="padding: 15px;">
                <div class="flex flex-row justify-between w-full gap-[20px]">
                    <p class="text-[20px] font-bold h-[20px]">{user.firstName} {user.lastName}</p>
                    <div class="flex flex-row">
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <!-- svelte-ignore a11y_no_static_element_interactions -->
                        <div class="flex self-end" style="margin-right: 15px;" on:click={() => {
                            editUser = user;
                            editUserEmail = user.email;
                            editUserFirstName = user.firstName;
                            editUserLastName = user.lastName;
                            editUserPopup = true;
                        }}>
                            <Pen
                                class="cursor-pointer hover:text-blue-500 transition-all"
                                size=20
                            />
                        </div>
                        {#if user._id != currentUser._id}
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <div class="flex self-end" style="margin-right: 12.5px;" on:click={() => {
                                if (user.disabled) {
                                    enableUser = user;
                                    enableUserPopup = true;
                                } else {
                                    disableUser = user;
                                    disableUserPopup = true;
                                }
                            }}>
                                {#if user.disabled}
                                    <UserCheck
                                        class="cursor-pointer hover:text-green-600 transition-all"
                                        size=20
                                    />
                                {:else}
                                    <UserX
                                        class="cursor-pointer hover:text-red-600 transition-all"
                                        size=20
                                    />
                                {/if}
                            </div>
                        {/if}
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <!-- svelte-ignore a11y_no_static_element_interactions -->
                        <div class="flex self-end" on:click={() => {
                            deleteUser = user;
                            deleteUserPopup = true;
                        }}>
                            <Trash
                                class="cursor-pointer hover:text-red-600 transition-all"
                                size=20
                            />
                        </div>
                    </div>
                </div>
                <p class="text-[12px] opacity-35 h-[20px]">Created at {UserMinimal.getCreatedAt(user).getDate()}.{UserMinimal.getCreatedAt(user).getMonth()}.{UserMinimal.getCreatedAt(user).getFullYear()}</p>
                <TextField label="Email" value={user.email} readonly />
                <RoleList label="Roles" roles={roles.filter(r => user.roles.includes(r._id))} onAdd={() => {}} onRemove={() => {}} readOnly={false} isSystemAdmin={currentUser._id == UserMinimal.DEFAULT_USER_ID} disableOutline />
            </div>
        {/each}
    </div>
{/if}