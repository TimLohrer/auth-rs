<script lang="ts">
	import ScopeList from './../../../lib/components/global/ScopeList.svelte';
    import { onMount } from "svelte";
	import type AuthRsApi from "$lib/api";
	import AuthStateManager from "$lib/auth";
    import {
        Bot,
        Link,
        User as UserIcon,
        SquareArrowOutUpRight,
        Clock,
        Lock,
        CircleX,
		Info
    } from "lucide-svelte";
	import { INVALID_SCOPES, SCOPES } from "$lib/models/OAuthScopes";
	import User from "$lib/models/User";
	import OAuthApplication from "$lib/models/OAuthApplication";
	import { apiUrl } from '$lib/store/config';
	import DateUtils from '$lib/dateUtils';

    let api: AuthRsApi | null = null;
    let user: User | null = null;

    let currentPath: string | null = null;

    let oAuthData: {
        clientId: string;
        state: string;
        scopes: string[];
        invalidScopes: string[];
        redirect: string,
        redirectBase: string,
        activeSince: string,
    } = {
        clientId: '',
        state: '',
        scopes: [],
        invalidScopes: [],
        redirect: '',
        redirectBase: '',
        activeSince: ''
    };
    let oAuthApplication: OAuthApplication | null = null;

    let step = 0;

    async function authorize() {
        step = 1;
        api?.authorizeOAuthApplication(oAuthData.clientId, oAuthData.redirect, oAuthData.scopes)
            .then((data) => {
                window.location.href = `${oAuthData.redirect}?code=${data.code}&state=${oAuthData.state}`;
            })
            .catch((err) => {
                step = 0;
                console.error('Failed to authorize OAuth application!', err);
            });
    }

    function cancel() {
        window.location.href = oAuthData.redirectBase;
    }

    onMount(async () => {
        currentPath = window.location.href;
        const url = new URL(currentPath);
        const clientId = url.searchParams.get('client_id');
        const state = url.searchParams.get('state');
        const scope = url.searchParams.get('scope');
        const redirect = url.searchParams.get('redirect_uri');

        if (!clientId || !state || !scope || !redirect) { 
            console.error('Missing parameters!');
            window.location.href = redirect ?? '/';
            return;
        }
        
        const pageData = await new AuthStateManager($apiUrl).handlePageLoad([`redirect_uri=${encodeURIComponent(currentPath)}`]);
        api = pageData?.[0] ?? null;
        user = pageData?.[1] ?? null;

        if (!api || !user) {
            console.error('Failed to load page data!');
            return;
        }

        let scopes = scope!.split(',').map(s => s.toLowerCase());
        scopes = scopes.filter((scope) => !INVALID_SCOPES.includes(scope));

        const invalidScopes = scopes.filter(scope => !Object.keys(SCOPES).includes(scope));
        scopes = scopes.filter(scope => scope.split(':')[1] != '*' ? !scopes.includes(`${scope.split(':')[0]}:*`): true);

        oAuthData = {
            clientId,
            state,
            scopes,
            invalidScopes,
            redirect,
            redirectBase: new URL(decodeURIComponent(redirect!)).origin,
            activeSince: ''
        };

        api.getOAuthApplication(clientId)
            .then((app) => {
                oAuthApplication = app;
                oAuthData.activeSince = `${DateUtils.getDateString(OAuthApplication.getCreatedAt(app))}`;
            })
            .catch((err) => {
                console.error('Failed to load OAuth application data!', err);
                window.location.href = redirect;
            });
    });
</script>

<div class="flex items-center justify-center h-screen w-screen">
    <div class="flex flex-col items-center border-[2.5px] rounded-md" style="padding: 30px; border-color: #333;">
        {#if user && User.isSystemAdmin(user)}
            <div class="flex flex-col items-center justify-center text-center gap-[25px] max-w-[500px]">
                <CircleX size="150" color="var(--color-red-500)" />
                <p>For security reasons, the system user can't authorize external OAuth Applications.</p>
                <a
                    class="text-blue-500 cursor-pointer opacity-75 hover:opacity-100 text-[18px] transition-all"
                    href="/logout?redirect_uri={encodeURIComponent(currentPath ?? '/')}"
                >&rarr; <i>Switch Account</i> &larr;</a>
            </div>
        {:else if oAuthData.clientId.length > 0 && (oAuthData.scopes.length < 1 || oAuthData.invalidScopes.length > 0)}
            <div class="flex flex-col items-center justify-center text-center gap-[25px] max-w-[500px]">
                <CircleX size="150" color="var(--color-red-500)" />
                {#if oAuthData.invalidScopes.length > 0}
                    <p>The following scopes are invalid:</p>
                    <p class="opacity-75">{oAuthData.invalidScopes.join(', ')}</p>
                {:else}
                    <p>Invalid scopes requested!</p>
                {/if}
                <a
                    class="text-blue-500 cursor-pointer opacity-75 hover:opacity-100 text-[18px] transition-all"
                    href={oAuthData.redirect ?? '/'}
                >&rarr; <i>Go back!</i> &larr;</a>
            </div>
        {:else}
            <div class="flex flex-col gap-2 items-center">
                <div class="flex flex-row items-center justify-center gap-[10px]" style="margin-bottom: 20px;">
                    <Bot class="size-[80px]" />
                    <p class="opacity-50" style="letter-spacing: 3.5px;">....</p>
                    <Link class="size-[20px] opacity-75" style="margin-top: 5px;" />
                    <p class="opacity-50" style="letter-spacing: 3.5px;">....</p>
                    <UserIcon class="size-[80px]" />
                </div>
                <h1 class="font-extrabold text-2xl" style="margin-bottom: 5px;">{(oAuthApplication?.name?.length ?? 0) > 24 ? oAuthApplication?.name.substring(0, 25) + '...' : oAuthApplication?.name}</h1>
                <h2 class="opacity-50 text-[14px]">wants to access your Account.</h2>
                <div class="flex flex-row gap-[10px] text-[12px]">
                    <p class="opacity-50">Signed in as</p>
                    <p class="opacity-85">{user?.firstName} {user?.lastName}</p>
                    <a class="text-blue-400" style="margin-left: 7.5px;" href="/logout?redirect_uri={encodeURIComponent(currentPath ?? '/')}">Not you?</a>
                </div>
            </div>
            <hr class="h-[2px] w-full bg-white opacity-25 rounded-[2px]" style="margin: 15px;" />
            <div class="flex flex-col items-center gap-[10px] w-full" style="padding: 2.5px 17.5px;">
                <ScopeList scopes={oAuthData.scopes} />
            </div>
            <hr class="h-[2px] w-full bg-white opacity-25 rounded-[2px]" style="margin: 10px;" />
            <div class="flex flex-col items-start justify-center w-full max-w-[450px] gap-[10px]" style="padding: 2.5px 17.5px;">
                <div class="flex flex-row items-center gap-[15px]">
                    <SquareArrowOutUpRight class="w-[20px] h-[20px] opacity-50" />
                    <p class="text-[11px]">
                        <span class="opacity-50">Once you authorize you will be redirected to:</span>
                        <span class="font-bold opacity-85">{oAuthData.redirectBase}</span>
                    </p>
                </div>
                <div class="flex flex-row items-center gap-[12.5px]">
                    <Clock class="w-[17.5px] h-[17.5px] opacity-50" />
                    <p class="text-[11px] opacity-85"><span class="opacity-70">Active since</span> {oAuthData.activeSince}</p>
                </div>
                <div class="flex flex-row items-center gap-[12.5px]">
                    <Lock class="w-[30px] h-[30px] opacity-50" />
                    <p class="text-[11px] opacity-70">This application will never be able to access anything outside of the permissions mentioned above.</p>
                </div>
                {#if oAuthData.scopes.some(s => s.includes('user_data_storage:'))}
                    <div class="flex flex-row items-center gap-[12.5px]">
                        <Info class="w-[55px] h-[55px] opacity-50" />
                        <p class="text-[11px] opacity-70">The application will NOT be able to read and write data about your profile. The "additional data storage" permission is used to read and write generic data that is linked to your account.</p>
                    </div>
                {/if}
            </div>
            <hr class="h-[2px] w-full bg-white opacity-25 rounded-[2px]" style="margin: 10px;" />
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <div class="flex flex-row items-center justify-between w-full" style="margin-top: 10px;">
                <h1
                    class="text-red-500 cursor-pointer btn cancel"
                    class:opacity-50={step != 0}
                    on:click={step == 0 ? cancel : null}
                >Cancel</h1>
                <h1
                    class="text-green-500 font-bold cursor-pointer btn authorize"
                    class:opacity-50={step != 0}
                    on:click={step == 0 ? authorize : null}
                >{step == 0 ? 'Authorize' : 'Authorizing...'}</h1>
            </div>
        {/if}
    </div>
</div>

<style>
    .btn {
        transition: all 0.2s;
    }
    
    .btn:hover {
        opacity: 75%;
    }
</style>

