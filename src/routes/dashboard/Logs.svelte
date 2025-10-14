<script lang="ts">
	import type AuthRsApi from "$lib/api";
	import AuditLogEntry from "$lib/components/dashboard/AuditLogEntry.svelte";
	import { AuditLog } from "$lib/models/AuditLog";
	import type OAuthApplication from "$lib/models/OAuthApplication";
	import Passkey from "$lib/models/Passkey";
	import type RegistrationToken from "$lib/models/RegistrationToken";
	import type Role from "$lib/models/Role";
	import User from "$lib/models/User";
	import { onMount } from "svelte";

    export let api: AuthRsApi;
    export let user: User;
    export let users: User[];
    export let roles: Role[];
    export let applications: OAuthApplication[];
    export let registrationTokens: RegistrationToken[];
    export let passkeys: Passkey[];
    export let auditLogs: AuditLog[];
    export let isGlobalLogs: boolean = false;

    onMount(async () => {
        api.getAuditLogs(isGlobalLogs ? null : user).then((newAuditLogs) => {
            auditLogs = newAuditLogs.sort((a, b) => {
                // Sort by createdAt descending
                return AuditLog.getCreatedAt(b).getTime() - AuditLog.getCreatedAt(a).getTime();
            });
            
            if (isGlobalLogs && users.length <= 0) {
                // TODO: request users individually when making audit logs paginated
                api.getUsers().then((newUsers) => {
                    users = newUsers;
                }).catch((err) => {
                    console.error(err);
                });
            } else if (!isGlobalLogs && users.length <= 0) {
                users = [user];
            }
            if (isGlobalLogs && roles.length <= 0) {
                api.getAllRoles().then((newRoles) => {
                    roles = newRoles;
                }).catch((err) => {
                    console.error(err);
                });
            }
            if (isGlobalLogs && registrationTokens.length <= 0) {
                api.getAllRegistrationTokens().then((newRegistrationTokens) => {
                    registrationTokens = newRegistrationTokens;
                }).catch((err) => {
                    console.error(err);
                });
            }
            if (applications.length <= 0) {
                api.getOAuthApplications().then((newApplications) => {
                    applications = newApplications;
                }).catch((err) => {
                    console.error(err);
                });
            }
            if (isGlobalLogs) {
                api.getAllPasskeys().then((newPasskeys) => {
                    passkeys = newPasskeys;
                }).catch((err) => {
                    console.error(err);
                });
            } else if (passkeys.length <= 0) {
                api.getUserPasskeys(user.id).then((newPasskeys) => {
                    passkeys = newPasskeys;
                }).catch((err) => {
                    console.error(err);
                });
            }
        }).catch((err) => {
            console.error(err);
        });
    })
</script>

<div class="flex flex-col overflow-y-scroll gap-[15px]">
    {#each auditLogs as auditLog}
        <AuditLogEntry bind:user bind:auditLog bind:users bind:roles bind:applications bind:registrationTokens bind:passkeys />
    {/each}
</div>