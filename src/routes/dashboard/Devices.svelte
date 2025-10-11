<script lang="ts">
	import ScopeList from '../../lib/components/global/ScopeList.svelte';
	import type AuthRsApi from "$lib/api";
	import OAuthConnection from "$lib/models/OAuthConnection";
	import type User from "$lib/models/User";
	import { Laptop, LogOut, Trash, Unlink } from "lucide-svelte";
	import { onMount } from "svelte";
	import Popup from '$lib/components/global/Popup.svelte';
	import DateUtils from '$lib/utils/dateUtils';
	import Tooltip from 'sv-tooltip';
	import { jsonAction } from '$lib/utils/jsonAttributes';
	import Device from '$lib/models/Device';
	import AuthStateManager from '$lib/auth';
	import { apiUrl } from '$lib/store/config';
	import TotpInput from '$lib/components/auth/TotpInput.svelte';
	import TextInput from '$lib/components/global/TextInput.svelte';

    export let api: AuthRsApi;
    export let user: User;

    let removeDevicePopup: boolean = false;
    let removeDevice: Device | null = null;

    let logoutAllDevicesPopup: boolean = false;
    let password: string = '';

    async function logoutAll(password: string | null, totp: string | null): Promise<boolean> {
        api.deleteAllDevicesForUser(user._id, password, totp)
            .then(() => {
                user.devices = [];
                const authStateManager = new AuthStateManager($apiUrl);
                authStateManager.logout();
            })
            .catch(e => console.error(e));
        return false;
    }
</script>

{#if removeDevicePopup}
    <Popup title="Remove Device" onClose={() => {removeDevicePopup = false; removeDevice = null;}}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to remove this device?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
                style="margin-top: 25px;"
                on:click={() => {
                    removeDevicePopup = false;
                    api.deleteUserDevice(user._id, removeDevice!.id)
                        .then(() => {
                            user.devices = user.devices.filter(d => d.id != removeDevice!.id);
                            const authStateManager = new AuthStateManager($apiUrl);
                            if (removeDevice!.id == authStateManager.getActiveDeviceId()) {
                                authStateManager.logout();
                            }
                        })
                        .catch(e => console.error(e));
                }}
            >Remove</p>
        </div>
    </Popup>
{/if}

{#if logoutAllDevicesPopup}
    <Popup title="Logout All Devices" onClose={() => {logoutAllDevicesPopup = false;}}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to logout all devices? This will log you out of your current session as well.</p>
            <div class="flex flex-col items-center w-full" style="margin-top: 25px;">
                {#if user.mfa}
                    <p class="text-[14px] opacity-50" style="margin-bottom: 10px;">Please cofirm your MFA code:</p>
                    <TotpInput totp={[]} disabled={false} completeTotp={async (totp) => {
                        logoutAllDevicesPopup = false;
                        return logoutAll(null, totp);
                    }} />
                {:else}
                    <TextInput label="Confirm Password" bind:value={password} type="password" autofocus />
                {/if}
            </div>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px]"
                class:opacity-50={password.length == 0 && !user.mfa}
                style="margin-top: 25px;"
                on:click={user.mfa || password.length > 0 ? () => {
                    logoutAllDevicesPopup = false;
                    logoutAll(null, null);
                } : () => {}}
            >Logout</p>
        </div>
    </Popup>
{/if}

{#if user.devices.length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <Unlink size="75" class="opacity-40" />
        <p class="text-[20px] opacity-50">You don't have any devices. (???)</p>
    </div>
{:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <p
            class="border-red-500 text-red-500 bg-black hover:bg-red-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md flex flex-row gap-2"
            style="padding: 10px;"
            on:click={() => {logoutAllDevicesPopup = true; password = '';}}
        ><LogOut /> Logout all devices</p>
    </div>
    <div class="flex flex-wrap w-full overflow-y-scroll overflow-x-hidden gap-[25px]">
        {#each user.devices as device}
            <div
                class="flex flex-col items-start justify start gap-[10px] min-h-[85px] border-[2px] border-[#333] rounded-md"
                style="padding: 15px;"
                use:jsonAction={{ data: device, title: "Device Data" }}
            >
                <div class="flex flex-row justify-between w-full">
                    <p class="text-[20px] font-bold h-[20px]">{(!device.os || device.os.toUpperCase() == 'OTHER' ? device.userAgent : device.os).substring(0, 22)}</p>
                    <div class="flex flex-row">
                        {#if device.id != new AuthStateManager($apiUrl).getActiveDeviceId()}
                            <Tooltip tip={"Remove Device"} bottom color="var(--color-red-600)">
                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                <div class="flex self-end" style="margin-left: 5px;" on:click={() => {
                                    removeDevice = device;
                                    removeDevicePopup = true;
                                }}>
                                    <Trash
                                        class="cursor-pointer hover:text-red-600 transition-all"
                                        size=20
                                    />
                                </div>
                            </Tooltip>
                        {:else}
                            <Tooltip tip={"Logout"} bottom color="var(--color-red-600)">
                                <!-- svelte-ignore a11y_click_events_have_key_events -->
                                <!-- svelte-ignore a11y_no_static_element_interactions -->
                                <div class="flex self-end" style="margin-left: 5px;" on:click={() => {
                                    removeDevice = device;
                                    removeDevicePopup = true;
                                }}>
                                    <LogOut
                                        color="var(--color-red-600)"
                                        class="cursor-pointer transition-all"
                                        style="margin-right: 5px;"
                                        size=20
                                    />
                                </div>
                            </Tooltip>
                            <Tooltip tip={"This is your current device"} bottom color="var(--color-green-600)">
                                <div class="flex self-end">
                                    <Laptop
                                        color="var(--color-green-600)"
                                        size=20
                                    />
                                </div>
                            </Tooltip>
                        {/if}
                    </div>
                </div>
                <p class="text-[12px] opacity-35 h-[10px]">Last used at {DateUtils.getFullDateString(Device.getCreatedAt(device))}</p>
            </div>
        {/each}
    </div>
{/if}