<script lang="ts">
	import { Circle } from 'svelte-loading-spinners';
	import TotpInput from '../../lib/components/auth/TotpInput.svelte';
	import Popup from '../../lib/components/global/Popup.svelte';
	import { ClockFading, KeyRound, Pen, Search, ShieldCheck, ShieldX, Trash, X } from 'lucide-svelte';
	import type AuthRsApi from "$lib/api";
	import type User from "$lib/models/User";
	import { goto } from '$app/navigation';
	import TextInput from '$lib/components/global/TextInput.svelte';
	import Passkey from '$lib/models/Passkey';
	import { onMount } from 'svelte';
	import Tooltip from 'sv-tooltip';
	import DateUtils from '$lib/utils/dateUtils';
	import PasskeyUpdates from '$lib/models/PasskeyUpdates';
	import { jsonAction } from '$lib/utils/jsonAttributes';

    export let api: AuthRsApi;
    export let user: User;
    export let passkeys: Passkey[];

    let activeTabIndex = 0;
    let tabs = [
        { name: '2FA', icon: ClockFading },
        { name: 'Passkeys', icon: KeyRound }
    ];
    let supportsPasskeys = false;
    let registeringPasskey = false;

    $: passkeyList = () => {
        const base = passkeys.filter(p => p.owner == user.id);
        const REGISTER_BUTTON = new Passkey("REGISTER_BUTTON", user.id, "Register Passkey", 0);
        if (supportsPasskeys) {
            base.push(REGISTER_BUTTON);
        }
        return base;
    }

    let startEnable2FAPopup = false;
    let completeEnable2FAPopup = false;
    let disable2FAPopup = false;
    
    let enablePassword = '';
    let showEnablePassword = false;
    
    let enableTotpQR: string | null = null;
    let enableTotp: (string | null)[] = [null, null, null, null, null, null];
    
    let disablePassword = '';
    let showDisablePassword = false;

    let editPasskeyPopup: boolean = false;
    let editPasskey: Passkey | null = null;
    let editPasskeyName: string = '';
    let suppressPasskeyUpdateToast: boolean = false;

    let deletePasskeyPopup: boolean = false;
    let deletePasskey: Passkey | null = null;

    async function showEnableMFAPopup() {
        enablePassword = '';
        showEnablePassword = false;
        startEnable2FAPopup = true;
    }

    async function enableMFA(code: string): Promise<boolean> {
        if (enableTotpQR) {
            api.mfa(code).then((newUser: User) => {
                completeEnable2FAPopup = false;
                user = newUser;
                goto('/logout');
                return true;
            }).catch(e => {
                console.error(e);
                enableTotp = [null, null, null, null, null, null];
                return false;
            });

            return true;
        } else {
            return false;
        }
    }

    async function createPasskey() {
        if (registeringPasskey) return;
        registeringPasskey = true;
        api.registerPasskey().then(passkey => {
            registeringPasskey = false;
            passkeys = [...passkeys, passkey];
            editPasskey = passkey;
            editPasskeyName = "";
            editPasskeyPopup = true;
            suppressPasskeyUpdateToast = true;
        }).catch(e => {
            console.error(e);
            registeringPasskey = false;
        });
    }

    async function showDisableMFAPopup() {
        disablePassword = '';
        showDisablePassword = false;
        disable2FAPopup = true;
    }

    onMount(() => {
        supportsPasskeys = window.PublicKeyCredential != null;

        if (supportsPasskeys && passkeys.length < 1) {
            api.getUserPasskeys(user.id).then((newPasskeys: Passkey[]) => {
                passkeys = newPasskeys;
            });
        }
    })
</script>

{#if editPasskeyPopup}
    <Popup title="Edit Passkey" onClose={() => editPasskeyPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <TextInput label="Name" bind:value={editPasskeyName} autofocus />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editPasskeyName.length > 3 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px] green-button"
                style="margin-top: 20px; margin-bottom: 10px;"
                on:click={editPasskeyName.length > 3 ? () => {
                    editPasskeyPopup = false;
                    api.updatePasskey(editPasskey?.id!, new PasskeyUpdates({ name: editPasskeyName }), suppressPasskeyUpdateToast)
                        .then(newPasskey => {
                            passkeys = passkeys.map(p => p.id === newPasskey.id ? newPasskey : p);
                            suppressPasskeyUpdateToast = false;
                        }).catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if deletePasskeyPopup}
    <Popup title="Delete Passkey" onClose={() => deletePasskeyPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to delete the passkey "{deletePasskey?.name}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px] red-button"
                style="margin-top: 25px;"
                on:click={() => {
                    deletePasskeyPopup = false;
                    api.deletePasskey(deletePasskey?.id!)
                        .then(() => {
                            passkeys = passkeys.filter(p => p.id !== deletePasskey?.id);
                        }).catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

<div class="flex flex-col items-center justify-start h-full w-full">
    <div class="flex flex-row gap-25px outline-[2px] outline-[#333] rounded-md" style="padding: 5px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        {#each tabs as tab, index}
            <!-- svelte-ignore a11y_no_static_element_interactions -->
            <div
                class="flex flex-row items-center justify-center gap-[10px] rounded-md w-[140px]"
                class:bg-blue-500={activeTabIndex == index}
                class:cursor-default={activeTabIndex == index}
                class:cursor-pointer={activeTabIndex != index}
                on:click={() => activeTabIndex = index}
                style="padding: 10px;"
            >
                <svelte:component this={tab.icon} height="10px" width="10px" />
                <p class="text-[16px]">{tab.name}</p>
            </div>
        {/each}
    </div>
    {#if activeTabIndex == 0}
        <div class="flex flex-col items-center justify-center h-full">
            {#if user.mfa}
                <ShieldCheck size="120" class="text-green-600" />
            {:else}
                <ShieldX size="120" class="text-red-600" />
            {/if}
            <p class="text-[24px]" style="margin-top: 10px;">2FA is {user.mfa ? 'enabled' : 'disabled'}.</p>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_static_element_interactions -->
            <div
                class="flex flex-row items-center justify-center gap-[15px] w-[275px] border-[2px] border-[#222] rounded-md cursor-pointer transition-all {user.mfa ? 'hover:text-red-600 hover:border-red-600' : 'hover:text-green-600 hover:border-green-600'}"
                style="padding: 10px 15px; margin-top: 20%;"
                on:click={user.mfa ? showDisableMFAPopup : showEnableMFAPopup}
            >
                {#if user.mfa}
                    Disable MFA
                {:else}
                    Enable MFA
                {/if}
            </div>
        </div>
    {:else if activeTabIndex == 1}
        <div class="flex flex-col h-full w-full" style="margin-top: 25px;">
            {#if window.location.protocol == 'https:'}
                {#if passkeys.filter(p => p.owner == user.id).length < 1}
                    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
                        <Search size="75" class="opacity-40" />
                        <p class="text-[20px] text-center opacity-50">You dont have any passkeys registered.</p>
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <!-- svelte-ignore a11y_no_static_element_interactions -->
                        <div
                            class="border-blue-500 text-blue-500 transition-all border-[1.5px] cursor-default rounded-md"
                            class:opacity-50={!supportsPasskeys}
                            class:hover:bg-blue-500={supportsPasskeys}
                            class:hover:text-white={supportsPasskeys}
                            class:hover:cursor-pointer={supportsPasskeys}
                            class:bg-blue-500={supportsPasskeys && registeringPasskey}
                            class:text-white={supportsPasskeys && registeringPasskey}
                            class:cursor-pointer={supportsPasskeys && registeringPasskey}
                            style="padding: 10px; margin-top: 25px;"
                            on:click={supportsPasskeys ? createPasskey : () => {}}
                        >
                            <div class="flex flex-row items-center gap-[10px]">
                                {#if registeringPasskey}
                                    <Circle size=17.5 color="white" />
                                    <p class="text-[17px]">Waiting for browser</p>
                                {:else}
                                    <KeyRound size=20 />
                                    <p class="text-[17px]">Register Passkey</p>
                                {/if}
                            </div>
                        </div>
                        {#if !supportsPasskeys}
                            <Tooltip tip="Your browser doesn't support passkeys." bottom color="var(--color-red-600)">
                                <!-- svelte-ignore element_invalid_self_closing_tag -->
                                <div class="absolute w-[160px] h-[45px] z-10" style="top: -70px; left: -80px;" />
                            </Tooltip>
                        {/if}
                    </div>
                {:else}
                    <div class="flex flex-wrap overflow-y-scroll overflow-x-hidden gap-[25px]">
                        {#each passkeyList() as passkey}
                            <!-- svelte-ignore a11y_no_static_element_interactions -->
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <div
                                class="flex flex-col gap-[25px] min-w-[250px] max-w-[400px] min-h-[100px] border-[2px] border-[#333] rounded-md transition-all"
                                class:items-start={passkey.id != 'REGISTER_BUTTON'}
                                class:items-center={passkey.id == 'REGISTER_BUTTON'}
                                class:justify-center={passkey.id == 'REGISTER_BUTTON'}
                                class:cursor-pointer={passkey.id == 'REGISTER_BUTTON'}
                                class:border-dashed={passkey.id == 'REGISTER_BUTTON'}
                                class:hover:border-blue-500={passkey.id == 'REGISTER_BUTTON'}
                                class:hover:text-blue-500={passkey.id == 'REGISTER_BUTTON'}
                                class:hover:border-solid={passkey.id == 'REGISTER_BUTTON'}
                                class:border-blue-500={passkey.id == 'REGISTER_BUTTON' && registeringPasskey}
                                class:text-blue-500={passkey.id == 'REGISTER_BUTTON' && registeringPasskey}
                                class:border-solid={passkey.id == 'REGISTER_BUTTON' && registeringPasskey}
                                on:click={passkey.id == 'REGISTER_BUTTON' ? createPasskey : () => {}}
                                style="padding: 15px;"
                            >
                                {#if passkey.id == 'REGISTER_BUTTON'}
                                    <div class="flex flex-row items-center gap-[10px]">
                                        {#if registeringPasskey}
                                            <Circle size=17.5 color="var(--color-blue-500)" />
                                            <p class="text-[15px]">Waiting for browser</p>
                                        {:else}
                                            <KeyRound size=20 class="hover:text-blue-500" />
                                            <p class="text-[17px]">Register Passkey</p>
                                        {/if}
                                    </div>
                                {:else}
                                    <div class="flex flex-row justify-between gap-[20px] w-full" use:jsonAction={{ data: passkey, title: "Passkey Data" }}>
                                        <p class="text-[20px] font-bold h-[20px]">{passkey.name.length > 20 ? passkey.name.substring(0, 19) + '...' : passkey.name}</p>
                                        <div class="flex flex-row">
                                            <Tooltip tip="Edit Passkey" bottom>
                                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                                <div class="flex self-end" style="margin-right: 12.5px;" on:click={() => {
                                                    editPasskey = passkey;
                                                    editPasskeyName = passkey.name;
                                                    editPasskeyPopup = true;
                                                }}>
                                                    <Pen
                                                        class="cursor-pointer hover:text-blue-500 transition-all"
                                                        size=20
                                                    />
                                                </div>
                                            </Tooltip>
                                            <Tooltip tip="Delete Passkey" bottom color="var(--color-red-600)">
                                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                                <div class="flex self-end" on:click={() => {
                                                    deletePasskey = passkey;
                                                    deletePasskeyPopup = true;
                                                }}>
                                                    <Trash
                                                        class="cursor-pointer hover:text-red-600 transition-all"
                                                        size=20
                                                    />
                                                </div>
                                            </Tooltip>
                                        </div>
                                    </div>
                                    <p class="text-[14px] opacity-35 h-[20px]">Created at {DateUtils.getDateString(Passkey.getCreatedAt(passkey))}</p>
                                {/if}
                            </div>
                        {/each}
                    </div>
                {/if}
            {:else}
                <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
                    <X size="75" color="var(--color-red-600)" />
                    <p class="text-[20px] text-center opacity-50">Passkeys are not available in non-https environments :/</p>
                </div>
            {/if}
        </div>
    {/if}
</div>

{#if startEnable2FAPopup}
    <Popup title="Enable MFA" onClose={() => startEnable2FAPopup = false}>
        <div class="flex flex-col items-center justify-center w-full" style="margin-top: 10px; margin-bottom: 10px;">
            <TextInput type="password" label="" placeholder="Confirm Password" bind:value={enablePassword} autocomplete="current-password" autofocus />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md cursor-pointer text-[18px]"
                style="margin-top: 25px;"
                class:enabled={enablePassword.length > 0}
                on:click={enablePassword.length > 0 ? () => {
                    startEnable2FAPopup = false;
                    enableTotp = [null, null, null, null, null, null];
                    completeEnable2FAPopup = true;
                    api.enableMfa(user, enablePassword)
                        .then((enableData: { token: string; }) => {
                            startEnable2FAPopup = false;
                            enableTotpQR = enableData.token;
                        })
                } : null}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if completeEnable2FAPopup}
    <Popup title="Complete MFA activation" onClose={() => completeEnable2FAPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[500px]" style="margin-top: 20px; margin-bottom: 20px;">
            <img src="data:image/png;base64,{enableTotpQR}" alt="MFA QR Code" class="w-[200px] h-[200px] rounded-md" />
            <p class="text-[14px] opacity-50 text-center" style="margin-top: 15px; margin-bottom: 15px;">Scan the QR code with your authenticator app and enter the 6 digit code below to complete the activation.</p>
            <TotpInput bind:totp={enableTotp} completeTotp={enableMFA} disabled={false} />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 cursor-default rounded-md text-[18px] opacity-50 transition-all"
                style="margin-top: 25px;"
                class:opacity-100={enableTotp.filter(c => c != null).length === 6}
                class:cursor-pointer={enableTotp.filter(c => c != null).length === 6}
                on:click={() => enableMFA(enableTotp.join(''))}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if disable2FAPopup}
    <Popup title="Disable MFA" onClose={() => disable2FAPopup = false}>
        <div class="flex flex-col items-center justify-center w-full" style="margin-top: 10px; margin-bottom: 10px;">
            <TotpInput totp={[]} disabled={false} completeTotp={async (code: string) => await api.disableMfa(user, code).then(newUser => {disable2FAPopup = false; user = newUser; goto('/logout'); return true}).catch((e) => {return false})}  />
        </div>
    </Popup>
{/if}