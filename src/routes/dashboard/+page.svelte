<script lang="ts">
	import Security from './Security.svelte';
	import SidebarButton from '$lib/components/dashboard/SidebarButton.svelte';
	import VersionInfo from '$lib/components/dashboard/VersionInfo.svelte';
	import Profile from './Profile.svelte';
	import AuthRsApi from "$lib/api";
	import AuthStateManager from "$lib/auth";
	import { onMount } from "svelte";
	import User from '$lib/models/User';
	import type OAuthApplication from '$lib/models/OAuthApplication';
	import Connections from './Connections.svelte';
	import type OAuthConnection from '$lib/models/OAuthConnection';
	import Applications from './Applications.svelte';
	import Logs from './Logs.svelte';
	import type { AuditLog } from '$lib/models/AuditLog';
	import Roles from './Roles.svelte';
	import type Role from '$lib/models/Role';
	import Users from './Users.svelte';
	import type Settings from '$lib/models/Settings';
	import SystemSettings from './SystemSettings.svelte';
	import type RegistrationToken from '$lib/models/RegistrationToken';
	import RegistrationCodes from './RegistrationCodes.svelte';
	import type Passkey from '$lib/models/Passkey';
	import { apiUrl, debugMode } from '$lib/store/config';
	import Devices from './Devices.svelte';

    const authStateManager = new AuthStateManager($apiUrl);
    let api = new AuthRsApi($apiUrl);

    let currentTabIndex = 0;

    let settings: Settings | null = null;
    let user: User | null = null;
    let users: User[] = [];
    let roles: Role[] = [];
    let connections: OAuthConnection[] = [];
    let applications: OAuthApplication[] = [];
    let auditLogs: AuditLog[] = [];
    let registrationTokens: RegistrationToken[] = [];
    let passkeys: Passkey[] = [];

    const TABS: {
        slug: string,
        name: string;
        icon: string;
        shouldShow: (user: User, settings: Settings) => boolean;
    }[] = [
        { slug: 'your-profile', name: 'Your Profile', icon: 'user', shouldShow: () => true },
        { slug: 'security', name: 'Security', icon: 'shield', shouldShow: () => true },
        { slug: 'devices', name: 'Devices', icon: 'laptop', shouldShow: () => true },
        { slug: 'connections', name: 'Connections', icon: 'link', shouldShow: (user) => !User.isSystemAdmin(user) },
        { slug: 'oauth-applications', name: 'OAuth Applications', icon: 'code-xml', shouldShow: (user, settings) => settings.allowOauthAppsForUsers || User.isAdmin(user) },
        { slug: 'logs', name: 'Logs', icon: 'clipboard-list', shouldShow: () => true },
        { slug: 'spacer', name: 'SPACER', icon: '', shouldShow: (user) => User.isAdmin(user) },
        { slug: 'users', name: 'Users', icon: 'users', shouldShow: (user) => User.isAdmin(user) },
        { slug: 'roles', name: 'Roles', icon: 'crown', shouldShow: (user) => User.isAdmin(user) },
        { slug: 'all-oauth-applications', name: 'All OAuth Apps', icon: 'code-xml', shouldShow: (user) => User.isAdmin(user) },
        { slug: 'registration-codes', name: 'Registration Codes', icon: 'ticket-check', shouldShow: (user) => User.isAdmin(user) },
        { slug: 'global-logs', name: 'Global Logs', icon: 'scroll-text', shouldShow: (user) => User.isAdmin(user) },
        { slug: 'system-settings', name: 'System Settings', icon: 'settings', shouldShow: (user) => User.isSystemAdmin(user) },
    ];
    
    onMount(async () => {
        const loadData = await authStateManager.handlePageLoad(['redirect_uri=/dashboard']);
        if (loadData) {
            api = loadData[0];
            user = loadData[1];
            settings = await api.getSettings();
        }
    })
</script>

<div class="flex w-screen h-screen items-center justify-center">
    <div class="flex flex-row items-center h-[80%] w-[70%] border-[2.5px] border-[#333] rounded-md" class:border-blue-500={$debugMode} style="padding: 10px;">
        <div class="flex flex-col justify-between {user && User.isSystemAdmin(user) ? 'h-[95%]' : 'h-[90%]'}">
            <div class="flex flex-col gap-[15px] overflow-y-scroll" style="padding-right: 7.5px;">
                {#each TABS as tab, index}
                    {#if user && settings && tab.shouldShow(user, settings)}
                        {#if tab.name == 'SPACER'}
                            <!-- svelte-ignore element_invalid_self_closing_tag -->
                            <div class="flex items-center justify-center w-[275px] h-[2px] bg-[#333]" style="margin-top: 20px;">
                                <p class="flex text-center text-[14px] bg-black" style="padding: 0 10px;">Admin</p>
                            </div>
                        {:else}
                            <SidebarButton tab={tab} active={currentTabIndex == index} selectTab={() => currentTabIndex = index} />
                        {/if}
                    {/if}
                {/each}
            </div>
            <div class="flex flex-col items-center gap-[10px]">
                <SidebarButton tab={{ name: 'Logout', icon: 'log-out' }} active={false} selectTab={() => authStateManager.logout()} isLogout={true} />
                <VersionInfo bind:user={user!} />
            </div>
        </div>
        <!-- svelte-ignore element_invalid_self_closing_tag -->
        <div class="w-[4px] h-[90%] bg-[#333] rounded-[2px]" style="margin: 0 15px 0 7.5px;" />
        <div class="flex flex-col h-[90%] w-full">
            {#if user && roles}
                <div class="flex items-center min-h-[75px]">
                    <p class="text-[14px]">>{currentTabIndex > 4 ? ' Admin' : ''} Dashboard > {TABS[currentTabIndex].name}</p>
                </div>
                {#if TABS[currentTabIndex].slug == 'your-profile'}
                    <Profile bind:api bind:user bind:roles />
                {:else if TABS[currentTabIndex].slug == 'security'}
                    <Security bind:api bind:user bind:passkeys />
                {:else if TABS[currentTabIndex].slug == 'devices'}
                    <Devices bind:api bind:user />
                {:else if TABS[currentTabIndex].slug == 'connections'}
                    <Connections bind:api bind:user bind:connections />
                {:else if TABS[currentTabIndex].slug == 'oauth-applications'}
                    <Applications bind:api bind:user bind:users bind:applications onlyShowOwned={true} />
                {:else if TABS[currentTabIndex].slug == 'logs'}
                    <Logs bind:api bind:user bind:users bind:roles bind:applications bind:auditLogs bind:registrationTokens bind:passkeys />
                {:else if TABS[currentTabIndex].slug == 'users'}
                    <Users bind:api bind:currentUser={user} bind:users bind:roles />
                {:else if TABS[currentTabIndex].slug == 'roles'}
                    <Roles bind:api bind:roles />
                {:else if TABS[currentTabIndex].slug == 'all-oauth-applications'}
                    <Applications bind:api bind:user bind:users bind:applications onlyShowOwned={false} />
                {:else if TABS[currentTabIndex].slug == 'registration-codes'}
                    <RegistrationCodes bind:api bind:users bind:currentUser={user} bind:roles bind:registrationTokens />
                {:else if TABS[currentTabIndex].slug == 'global-logs'}
                    <Logs bind:api bind:user bind:users bind:roles bind:applications bind:auditLogs bind:registrationTokens bind:passkeys isGlobalLogs />
                {:else if TABS[currentTabIndex].slug == 'system-settings'}
                    <SystemSettings bind:api bind:settings={settings!} />
                {/if}
            {/if}
        </div>
    </div>
</div>