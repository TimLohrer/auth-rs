<script lang="ts">
	import TextField from '$lib/components/dashboard/TextField.svelte';
	import Popup from './../../lib/components/global/Popup.svelte';
	import RedirectUriList from './../../lib/components/dashboard/RedirectUriList.svelte';
	import type AuthRsApi from "$lib/api";
	import OAuthApplication from "$lib/models/OAuthApplication";
	import { BotOff, Pen, Trash } from "lucide-svelte";
	import { onMount } from "svelte";
	import OAuthApplicationUpdates from '$lib/models/OAuthApplicationUpdates';
	import type UserMinimal from '$lib/models/User';

    export let api: AuthRsApi;
    export let user: UserMinimal;
    export let applications: OAuthApplication[];
    export let onlyShowOwned: boolean = true;

    $: filteredApplications = applications.filter(app => !onlyShowOwned || app.owner == user._id);

    let showNewApplicationPopup: boolean = false;
    let newApplication: OAuthApplication | null = null;
    let newApplicationName: string = '';
    let newApplicationDescription: string = '';
    let newApplicationRedirectUris: string = '';
    let newApplicationRedirectUrisError: boolean = false;

    let editApplicationPopup: boolean = false;
    let editApplication: OAuthApplication | null = null;
    let editApplicationName: string = '';
    let editApplicationDescription: string = '';

    let deleteApplicationPopup: boolean = false;
    let deleteApplication: OAuthApplication | null = null;

    let addRedirectUriPopup: boolean = false;
    let newRedirectUri: string = '';
    let newRedirectUriApplication: OAuthApplication | null = null;

    function openCreateApplicationPopup() {
        newApplication = null;
        newApplicationName = '';
        newApplicationDescription = '';
        newApplicationRedirectUris = '';
        newApplicationRedirectUrisError = false;
        showNewApplicationPopup = true;
    }

    function openAddRedirectUriPopup(application: OAuthApplication) {
        newRedirectUri = '';
        newRedirectUriApplication = application;
        addRedirectUriPopup = true;
    }

    function addRedirectUri(application: OAuthApplication) {
        addRedirectUriPopup = false;
        application.redirectUris.push(newRedirectUri);
        
        api.updateOAuthApplication(application, new OAuthApplicationUpdates({ name: null, description: null, redirectUris: application.redirectUris }))
            .then(newApplication => {
                applications[applications.map(app => app._id).indexOf(application._id)] = newApplication;
            }).catch(e => console.error(e));
    }

    function removeRedirectUri(application: OAuthApplication, redirectUri: string) {
        api.updateOAuthApplication(application, new OAuthApplicationUpdates({ name: null, description: null, redirectUris: application.redirectUris.filter(uri => uri != redirectUri) }))
            .then(newApplication => applications[applications.map(app => app._id).indexOf(application._id)] = newApplication)
            .catch(e => console.error(e));
    }

    onMount(() => {
        api.getOAuthApplications()
            .then(apps => applications = apps)
            .catch(e => console.error(e));
    });
</script>

{#if newApplication != null}
    <Popup title="Copy Application Secret" onClose={() => newApplication = null}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <p class="text-[14px] opacity-50 text-center" style="margin-bottom: 10px;">This is your applications ID and secret.<br>Copy it now, you will never be able to get it again!</p>
            <TextField label="ID" value={newApplication._id} fullWidth readonly />
            <TextField label="Secret" value={newApplication.secret!} readonly />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p class="text-[16px] text-green-600 cursor-pointer" style="margin-top: 20px; margin-bottom: 15px;" on:click={() => newApplication = null}>Okay</p>
        </div>
    </Popup>
{/if}

{#if showNewApplicationPopup}
    <Popup title="Create Application" onClose={() => showNewApplicationPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px] max-w-[400px]">
            <p class="text-[14px] self-start h-[17.5px] opacity-50">Name</p>
            <!-- svelte-ignore a11y_autofocus -->
            <input
                type="text"
                placeholder="Name"
                bind:value={newApplicationName}
                class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
                style="padding: 5px 10px; margin-top: 5px; margin-bottom: 10px;"
                autofocus
            >
            <p class="text-[14px] self-start h-[17.5px] opacity-50">Description</p>
            <input
                type="text"
                placeholder="Description"
                bind:value={newApplicationDescription}
                class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
                style="padding: 5px 10px; margin-top: 5px; margin-bottom: 10px;"
            >
            <p class="text-[14px] self-start h-[17.5px] opacity-50">Redirect URI's</p>
            <input
            type="text"
            placeholder="https://test.com/callback,https://test2.com/callback"
            bind:value={newApplicationRedirectUris}
            class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
            style="padding: 5px 10px; margin-top: 5px;"
            >
            {#if newApplicationRedirectUrisError}
                <p class="text-[14px] text-red-600 self-start h-[10px] opacity-75" style="margin-bottom: 20px;">Invalid redirect URI's. Make sure you use the following format: '[url1],[url2],[url3]'.</p>
            {/if}
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {newApplicationName.length > 3 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px] button green-button"
                style="margin-top: 25px; margin-bottom: 10px;"
                on:click={newApplicationName.length > 3 ? () => {
                    if (newApplicationRedirectUris.length > 0 && newApplicationRedirectUris.split(',').filter(uri => uri.includes('http') && uri.includes('://') && uri.includes('.')).length != newApplicationRedirectUris.split(',').length) {
                        newApplicationRedirectUrisError = true;
                        return;
                    }
                    showNewApplicationPopup = false;
                    api.createOAuthApplication(newApplicationName, newApplicationDescription.length > 0 ? newApplicationDescription : null, newApplicationRedirectUris.length > 0 ? newApplicationRedirectUris.split(',') : [])
                        .then(createdApplication => {
                            newApplication = createdApplication;
                            applications = [...applications, createdApplication]
                        })
                        .catch(console.error);
                } : null}
            >Create</p>
        </div>
    </Popup>
{/if}

{#if editApplicationPopup}
    <Popup title="Edit Application" onClose={() => editApplicationPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <p class="text-[14px] self-start h-[17.5px] opacity-50">Name</p>
            <!-- svelte-ignore a11y_autofocus -->
            <input
                type="text"
                placeholder="Name"
                bind:value={editApplicationName}
                class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
                style="padding: 5px 10px; margin-top: 5px; margin-bottom: 10px;"
                autofocus
            >
            <p class="text-[14px] self-start h-[17.5px] opacity-50">Description</p>
            <input
                type="text"
                placeholder="Description"
                bind:value={editApplicationDescription}
                class="border-[1.5px] border-gray-300 rounded-md opacity-75 w-full"
                style="padding: 5px 10px; margin-top: 5px;"
            >
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editApplicationName.length > 3 ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px] button green-button"
                style="margin-top: 25px;"
                on:click={editApplicationName.length > 3 ? () => {
                    editApplicationPopup = false;
                    api.updateOAuthApplication(editApplication!, new OAuthApplicationUpdates({ name: editApplicationName, description: editApplicationDescription, redirectUris: null }))
                        .then(newApplication => {
                            applications[applications.map(app => app._id).indexOf(editApplication!._id)] = newApplication;
                        })
                        .catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if deleteApplicationPopup}
    <Popup title="Delete Application" onClose={() => deleteApplicationPopup = false}>
        <div class="flex flex-col items-center justify-center max-w-[350px]" style="margin-top: 20px; margin-bottom: 20px;">
            <p class="text-[14px] text-center opacity-50">Are you sure you want to delete the application "{deleteApplication?.name}"?</p>
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-red-600 cursor-pointer rounded-md text-[18px] button red-button"
                style="margin-top: 25px;"
                on:click={() => {
                    deleteApplicationPopup = false;
                    api.deleteOAuthApplication(deleteApplication!)
                        .then(() => applications = applications.filter(app => app._id != deleteApplication!._id))
                        .catch(e => console.error(e));
                }}
            >Confirm</p>
        </div>
    </Popup>
{/if}

{#if addRedirectUriPopup}
    <Popup title="Add Redirect URI" onClose={() => addRedirectUriPopup = false}>
        <div class="flex flex-col items-center justify-center w-full" style="margin-top: 20px; margin-bottom: 20px;">
            <!-- svelte-ignore a11y_autofocus -->
            <input
                type="text"
                placeholder="https://example.com/callback"
                class="border-[1.5px] border-gray-300 rounded-md opacity-75 min-w-[350px]"
                style="padding: 5px 10px; margin-top: 5px;"
                bind:value={newRedirectUri}
                autofocus
            >
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md text-[18px] {newRedirectUri.includes('http') && newRedirectUri.includes('://') && newRedirectUri.includes('.') ? 'cursor-pointer' : 'cursor-default opacity-50'} button green-button"
                style="margin-top: 25px;"
                class:enabled={newRedirectUri.includes('http') && newRedirectUri.includes('://') && newRedirectUri.includes('.')}
                on:click={newRedirectUri.includes('http') && newRedirectUri.includes('://') && newRedirectUri.includes('.') ? () => addRedirectUri(newRedirectUriApplication!) : null}
            >Save</p>
        </div>
    </Popup>
{/if}

{#if filteredApplications.length < 1}
    <div class="flex flex-col items-center justify-center gap-[25px] h-full w-full">
        <BotOff size="75" class="opacity-40" />
        <p class="text-[20px] opacity-50">{onlyShowOwned ? 'You don\'t have any' : 'There are currently no'} OAuth apps.</p>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <p
                class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md button"
                style="padding: 10px; margin-top: 25px;"
                on:click={openCreateApplicationPopup}
            >Create Application</p>
    </div>
{:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <p
            class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md button"
            style="padding: 10px;"
            on:click={openCreateApplicationPopup}
        >Create Application</p>
    </div>
    <div class="flex flex-wrap overflow-y-scroll gap-[25px]">
        {#each filteredApplications as application}
            <div class="flex flex-col items-start justify start gap-[10px] min-w-[350px] max-w-[400px] min-h-[200px] border-[2px] border-[#333] rounded-md" style="padding: 15px;">
                <div class="flex flex-row justify-between w-full">
                    <p class="text-[20px] font-bold h-[20px]">{application.name}</p>
                    <div class="flex flex-row">
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <!-- svelte-ignore a11y_no_static_element_interactions -->
                        <div class="flex self-end" style="margin-right: 12.5px;" on:click={() => {
                            editApplication = application;
                            editApplicationName = application.name;
                            editApplicationDescription = application.description ?? '';
                            editApplicationPopup = true;
                        }}>
                            <Pen
                                class="cursor-pointer hover:text-blue-500 transition-all"
                                size=20
                            />
                        </div>
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <!-- svelte-ignore a11y_no_static_element_interactions -->
                        <div class="flex self-end" on:click={() => {
                            deleteApplication = application;
                            deleteApplicationPopup = true;
                        }}>
                            <Trash
                                class="cursor-pointer hover:text-red-600 transition-all"
                                size=20
                            />
                        </div>
                    </div>
                </div>
                <p class="text-[12px] opacity-35 h-[20px]">Created at {OAuthApplication.getCreatedAt(application).getDate()}.{OAuthApplication.getCreatedAt(application).getMonth()}.{OAuthApplication.getCreatedAt(application).getFullYear()}</p>
                <p class="text-[12px] opacity-50">{@html (application.description?.length ?? 0) > 1 ? application.description?.substring(0, 200) + ((application.description?.length ?? 0) > 200 ? '...' : '') : '<i>This application does not have a description.</i>'}</p>
                <RedirectUriList bind:redirectUris={application.redirectUris} onAdd={() => openAddRedirectUriPopup(application)} onRemove={(redirectUri) => removeRedirectUri(application, redirectUri)} />
            </div>
        {/each}
    </div>
{/if}

<style>
    input:focus {
        outline: none;
        border: solid 1.5px var(--color-blue-500);
    }

    ::-webkit-scrollbar {
        width: 5px;
    }

    ::-webkit-scrollbar-thumb {
        background-color: var(--color-blue-500);
        border-radius: 10px;
    }
</style>