<script lang="ts">
	import TextInput from '../../lib/components/global/TextInput.svelte';
	import Popup from '../../lib/components/global/Popup.svelte';
	import type AuthRsApi from "$lib/api";
	import { LockOpen, PackageOpen, Pen, Trash, UserCheck, UserX } from "lucide-svelte";
	import { onMount } from "svelte";
	import UserUpdates from '$lib/models/UserUpdates';
	import User from '$lib/models/User';
	import TextField from '$lib/components/global/TextField.svelte';
	import RoleList from '$lib/components/dashboard/RoleList.svelte';
	import type Role from '$lib/models/Role';
	import DateUtils from '$lib/utils/dateUtils';
	import Tooltip from 'sv-tooltip';
	import { jsonAction } from '$lib/utils/jsonAttributes';

    export let api: AuthRsApi;
    export let currentUser: User;
    export let users: User[];
    export let roles: Role[];

    let showNewUserPopup: boolean = false;
    let newUserEmail: string = '';
    let newUserFirstName: string = '';
    let newUserLastName: string = '';
    let newUserPassword: string = '';
    let newUserPasswordConfirm: string = '';

    let editUserPopup: boolean = false;
    let editUser: User | null = null;
    let editUserEmail: string = '';
    let editUserFirstName: string = '';
    let editUserLastName: string = '';
    let editUserPassword: string = '';
    let editUserPasswordConfirm: string = '';
    let showAddUserRolesPopup: User | null = null;
    let addUserRoles: Role[] = [];

    let disableUserPopup: boolean = false;
    let disableUser: User | null = null;

    let enableUserPopup: boolean = false;
    let enableUser: User | null = null;

    let disableTotpPopup: boolean = false;
    let disableTotpUser: User | null = null;

    let deleteUserPopup: boolean = false;
    let deleteUser: User | null = null;

    function openCreateUserPopup() {
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

    function removeRole(role: Role, user: User) {
        const updates = new UserUpdates({ 
            email: null, 
            password: null, 
            firstName: null, 
            lastName: null, 
            roles: user.roles.filter(r => r != role._id), 
            disabled: null 
        });
        api.updateUser(user, updates)
            .then(u => users[users.map(u => u._id).indexOf(user._id)] = u)
            .catch(e => console.error(e));
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
            <TextInput type="email" label="Email" bind:value={newUserEmail} autocomplete="email" autofocus />
            <TextInput label="First Name" bind:value={newUserFirstName} autocomplete="name" />
            <TextInput label="Last Name" bind:value={newUserLastName} autocomplete="family-name" />
            <TextInput type="password" label="Password" bind:value={newUserPassword} autocomplete="new-password" />
            <TextInput type="password" label="Confirm Password" bind:value={newUserPasswordConfirm} autocomplete="new-password" />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {newUserDataIsValid() ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 25px; margin-bottom: 10px;"
                on:click={newUserDataIsValid() ? () => {
                    showNewUserPopup = false;
                    api.createUser(newUserEmail, newUserPassword, newUserFirstName, newUserLastName, null)
                        .then(createdUser => {
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
            <TextInput type="email" label="Email" bind:value={editUserEmail} autofocus />
            <TextInput label="First Name" bind:value={editUserFirstName} />
            <TextInput label="Last Name" bind:value={editUserLastName} />
            <TextInput type="password" label="Password" bind:value={editUserPassword} />
            <TextInput type="password" label="Confirm Password" bind:value={editUserPasswordConfirm} />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editUserDataIsValid() ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 20px; margin-bottom: 10px;"
                on:click={editUserDataIsValid() ? () => {
                    editUserPopup = false;
                    api.updateUser(editUser!, new UserUpdates({ email: editUserEmail, password: editUserPassword.length < 1 ? null : editUserPassword, firstName: editUserFirstName, lastName: editUserLastName, roles: null, disabled: null }))
                        .then(editedUser => {
                            users[users.map(user => user._id).indexOf(editUser!._id)] = editedUser;
                        })
                        .catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if showAddUserRolesPopup}
    <Popup title="Add Roles" onClose={() => {showAddUserRolesPopup = null; addUserRoles = [];}}>
        <div class="flex flex-col items-center justify-center">
            {#if roles.filter(r => !users.find(u => u._id == showAddUserRolesPopup?._id)?.roles.includes(r._id)).length < 1}
                <i>User already has every role.</i>
                <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
                <!-- svelte-ignore a11y_click_events_have_key_events -->
                <p
                    class="text-red-600 rounded-md cursor-pointer text-[18px]"
                    style="margin-top: 20px; margin-bottom: 10px;"
                    on:click={() => showAddUserRolesPopup = null}
                >Close</p>
            {:else} 
                <div class="flex flex-wrap items-center justify-center overflow-y-scroll max-w-[500px] max-h-[300px] gap-[25px]">
                    {#each roles.filter(r => !users.find(u => u._id == showAddUserRolesPopup?._id)?.roles.includes(r._id)) as role}
                        <!-- svelte-ignore a11y_no_static_element_interactions -->
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <div
                            class="cursor-pointer {addUserRoles.map(r => r._id).includes(role._id) ? 'border-green-600' : 'border-[#333]'} border-[1px] rounded-md"
                            on:click={() => {
                                const roleIds = addUserRoles.map(r => r._id);
                                
                                if (roleIds.includes(role._id)) {
                                    addUserRoles = addUserRoles.filter(r => r._id != role._id);
                                } else {
                                    addUserRoles = [...addUserRoles, role];
                                }
                            }}
                            style="padding: 10px;"
                        >
                            <p>{role.name}</p>
                        </div>
                    {/each}
                </div>
                <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
                <!-- svelte-ignore a11y_click_events_have_key_events -->
                <p
                    class="text-green-600 rounded-md {addUserRoles.length > 0 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                    style="margin-top: 20px; margin-bottom: 10px;"
                    on:click={addUserRoles.length > 0 ? () => {
                        api.updateUser(showAddUserRolesPopup!, new UserUpdates({
                            email: null,
                            password : null,
                            firstName: null,
                            lastName: null,
                            roles: users.find(u => u._id == showAddUserRolesPopup?._id)?.roles.concat(addUserRoles.map(r => r._id)) ?? null,
                            disabled: null
                        })).then(editedUser => {
                            users[users.map(u => u._id).indexOf(showAddUserRolesPopup!._id)] = editedUser;
                            showAddUserRolesPopup = null;
                            addUserRoles = [];
                        }).catch(e => {
                            console.error(e);
                            showAddUserRolesPopup = null;
                            addUserRoles = [];
                        });
                    } : null}
                >Add</p>
            {/if}
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
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    disableUserPopup = false;
                    api.updateUser(disableUser!, new UserUpdates({ email: null, password: null, firstName: null, lastName: null, roles: null, disabled: true }))
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
                class="text-green-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    enableUserPopup = false;
                    api.updateUser(enableUser!, new UserUpdates({ email: null, password: null, firstName: null, lastName: null, roles: null, disabled: false }))
                        .then(enabledUser => {
                            users[users.map(user => user._id).indexOf(enableUser!._id)] = enabledUser;
                        })
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if disableTotpPopup}
    <Popup title="Disable MFA" onClose={() => disableTotpPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to disable MFA for "{disableTotpUser?.firstName} {disableTotpUser?.lastName}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    disableTotpPopup = false;
                    api.disableMfaForUser(currentUser, disableTotpUser!._id)
                        .then(disabledTOTPUser => {
                            users[users.map(user => user._id).indexOf(disableTotpUser!._id)] = disabledTOTPUser;
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
                class="text-green-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    enableUserPopup = false;
                    api.updateUser(enableUser!, new UserUpdates({ email: null, password: null, firstName: null, lastName: null, roles: null, disabled: false }))
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
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
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

{#if users.filter(u => u._id != User.DEFAULT_USER_ID).length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <PackageOpen size="75" class="opacity-40" />
            <p class="text-[20px] opacity-50">There are currently no users set up.</p>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <p
                class="border-blue-500 text-blue-500 bg-black hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
                style="padding: 10px; margin-top: 25px;"
                on:click={openCreateUserPopup}
            >Create User</p>
    </div>
{:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <p
            class="border-blue-500 text-blue-500 bg-black hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
            style="padding: 10px;"
            on:click={openCreateUserPopup}
        >Create User</p>
    </div>
    <div class="flex flex-wrap overflow-y-scroll overflow-x-hidden gap-[25px]">
        {#each users.filter(u => u._id != User.DEFAULT_USER_ID) as user}
            <div
                class="flex flex-col items-start justify start gap-[10px] min-w-[300px] border-[2px] border-[#333] rounded-md"
                style="padding: 15px;"
                use:jsonAction={{ data: user, title: "User Data" }}
            >
                <div class="flex flex-row justify-between w-full gap-[20px]">
                    <p class="text-[20px] font-bold h-[20px]">{`${user.firstName} ${user.lastName}`.length > 20 ? `${user.firstName} ${user.lastName}`.substring(0, 19) + '...' : `${user.firstName} ${user.lastName}`}</p>
                    <div class="flex flex-row">
                        <Tooltip tip="Edit User" bottom>
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
                        </Tooltip>
                        {#if user._id != currentUser._id}
                            <Tooltip tip={user.disabled ? 'Enable User' : 'Disable User'} bottom color={user.disabled ? undefined : "var(--color-red-600)"}>
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
                            </Tooltip>
                        {/if}
                        {#if User.isSystemAdmin(currentUser) && user.mfa}
                            <Tooltip tip="Disable MFA" bottom color="var(--color-red-600)">
                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                <div class="flex self-end" style="margin-right: 12.5px;" on:click={() => {
                                    disableTotpUser = user;
                                    disableTotpPopup = true;
                                }}>
                                    <LockOpen
                                        class="cursor-pointer hover:text-red-600 transition-all"
                                        size=20
                                    />
                                </div>
                            </Tooltip>
                        {/if}
                        <Tooltip tip="Delete User" bottom color="var(--color-red-600)">
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
                        </Tooltip>
                    </div>
                </div>
                <p class="text-[12px] opacity-35 {user.disabled ? 'h-[10px]' : 'h-[20px]'}">Created at {DateUtils.getFullDateString(User.getCreatedAt(user))}</p>
                {#if user.disabled}
                    <p class="text-[12px] h-[20px] text-red-600">Disabled!</p>
                {/if}
                <TextField
                    label="Email"
                    value={user.email}
                    readonly
                />
                <TextField
                    label="MFA"
                    value={user.mfa ? 'Enabled' : 'Disabled'}
                    readonly
                />
                <RoleList
                    label="Roles"
                    roles={roles.filter(r => user.roles.includes(r._id))}
                    onAdd={() => showAddUserRolesPopup = user}
                    onRemove={(role: Role) => removeRole(role, user)}
                    readOnly={false}
                    isSystemAdmin={currentUser._id == User.DEFAULT_USER_ID}
                    disableOutline
                />
            </div>
        {/each}
    </div>
{/if}