<script lang="ts">
	import TotpInput from '../../lib/components/auth/TotpInput.svelte';
	import Popup from '../../lib/components/global/Popup.svelte';
	import { Eye, EyeOff, ShieldCheck, ShieldX } from 'lucide-svelte';
	import type AuthRsApi from "$lib/api";
	import type User from "$lib/models/User";
	import { goto } from '$app/navigation';
	import TextInput from '$lib/components/global/TextInput.svelte';

    export let api: AuthRsApi;
    export let user: User;

    let startEnable2FAPopup = false;
    let completeEnable2FAPopup = false;
    let disable2FAPopup = false;
    
    let enablePassword = '';
    let showEnablePassword = false;
    
    let enableTotpQR: string | null = null;
    let enableTotp: (number | null)[] = [null, null, null, null, null, null];
    
    
    let disablePassword = '';
    let showDisablePassword = false;

    async function showEnableMFAPopup() {
        enablePassword = '';
        showEnablePassword = false;
        startEnable2FAPopup = true;
    }

    async function enableMFA() {
        if (enableTotpQR) {
            const totp = enableTotp.map(n => n === null ? 0 : n).join('');
            api.mfa(totp).then((newUser: User) => {
                completeEnable2FAPopup = false;
                user = newUser;
                goto('/logout');
            });
        }
    }

    async function showDisableMFAPopup() {
        disablePassword = '';
        showDisablePassword = false;
        disable2FAPopup = true;
    }
</script>

<div class="flex flex-col items-center justify-start h-full" style="padding-top: 10%;">
    {#if user.mfa}
        <ShieldCheck size="120" class="text-green-600" />
    {:else}
        <ShieldX size="120" class="text-red-600" />
    {/if}
    <p class="text-[24px]" style="margin-top: 10px;">MFA is {user.mfa ? 'enabled' : 'disabled'}.</p>
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

{#if startEnable2FAPopup}
    <Popup title="Enable MFA" onClose={() => startEnable2FAPopup = false}>
        <div class="flex flex-col items-center justify-center w-full" style="margin-top: 10px; margin-bottom: 10px;">
            <TextInput type="password" label="" placeholder="Confirm Password" bind:value={enablePassword} autofocus />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md text-[18px] button green-button"
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
                class="text-green-600 rounded-md text-[18px] button green-button"
                style="margin-top: 25px;"
                class:enabled={enableTotp.filter(c => c != null).length === 6}
                on:click={enableMFA}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if disable2FAPopup}
    <Popup title="Disable MFA" onClose={() => disable2FAPopup = false}>
        <div class="flex flex-col items-center justify-center w-full" style="margin-top: 10px; margin-bottom: 10px;">
            <TextInput type="password" label="" placeholder="Confirm Password" bind:value={disablePassword} autofocus />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 rounded-md text-[18px] button red-button"
                style="margin-top: 25px;"
                class:enabled={disablePassword.length > 0}
                on:click={disablePassword.length > 0 ? () => api.disableMfa(user, null, disablePassword).then(newUser => {disable2FAPopup = false; user = newUser; goto('/logout')}) : null}
            >Confirm</p>
        </div>
    </Popup>
{/if}

<style>
    .button {
        transition-duration: .2s;
        opacity: 0.5;
        cursor: default;
    }

    .button.enabled {
        opacity: 1;
        cursor: pointer;
    }

    .button.red-button.enabled:hover {
        background-color: transparent;
        color: var(--color-red-900);
    }

    .button.green-button.enabled:hover {
        background-color: transparent;
        color: var(--color-green-900);
    }
</style>